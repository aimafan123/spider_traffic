"""Continuous Collection 主循环与命令行入口。

一次循环 = 取调度决策 → 设置 keylog → 浏览器访问 → 写 ground truth → 随机间隔。
抓包进程在所有访问之间**持续运行**，只在跨时间桶时轮转文件。

用法::

    cd src && ../.venv/bin/python3 -m spider_traffic.continuous --config ../config/continuous.yaml
    # 或
    ./continuous.sh
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import threading
import time
from dataclasses import replace
from datetime import datetime
from typing import Any, Dict, Optional

from spider_traffic.continuous.browser import (
    BrowserError,
    BrowserSessionManager,
    ensure_direct_transport,
    kill_orphan_browsers,
)
from spider_traffic.continuous.capture import CaptureError, HourlyPcapCapture, safe_token
from spider_traffic.continuous.config import (
    DEFAULT_CONFIG_NAME,
    ConfigError,
    ContinuousConfig,
    default_config_path,
    load_config,
)
from spider_traffic.continuous.groundtruth import GroundTruthWriter, VisitRecord
from spider_traffic.continuous.logging_setup import get_logger
from spider_traffic.continuous.scheduling import SiteScheduler
from spider_traffic.continuous.sleeping import SleepSampler, interruptible_sleep

# sleep 采样与调度用不同的随机流，避免相互干扰（同一 seed 仍可复现）
_SLEEP_STREAM_SALT = 0x5EED


class ContinuousCollector:
    """连续采集器：负责调度、访问、记录与收尾。"""

    def __init__(self, cfg: ContinuousConfig, logger, project_logger_ok: bool = True) -> None:
        self.cfg = cfg
        self.logger = logger
        self.project_logger_ok = project_logger_ok
        self.stop_event = threading.Event()

        self.state_path = os.path.join(
            cfg.storage.state_dir, f"scheduler_state_{safe_token(cfg.vps.name)}.json"
        )
        self.state = self._load_state()
        self.seed, self.seed_source = self._resolve_seed()

        self.scheduler = SiteScheduler(
            monitored=cfg.monitored,
            background=cfg.background,
            ratio=cfg.sites.monitored_ratio,
            seed=self.seed,
            ratio_mode=cfg.sites.ratio_mode,
            background_sampling=cfg.sites.background_sampling,
            state=self.state.get("scheduler"),
        )
        self.sampler = SleepSampler(
            distribution=cfg.sleep.distribution,
            mean_seconds=cfg.sleep.mean_seconds,
            min_seconds=cfg.sleep.min_seconds,
            max_seconds=cfg.sleep.max_seconds,
            rng=random.Random(self.seed ^ _SLEEP_STREAM_SALT),
        )
        capture_cfg = replace(cfg.capture, enabled=False) if cfg.dry_run else cfg.capture
        self.capture = HourlyPcapCapture(capture_cfg, cfg.vps.name, logger)
        # 浏览器常驻、每 visits_per_browser 次访问重启一次；dry-run 不创建浏览器
        self.browser = None if cfg.dry_run else BrowserSessionManager(
            browser_name=cfg.browser.name,
            settle_seconds=cfg.browser.settle_seconds,
            page_load_timeout=cfg.browser.page_load_timeout,
            scroll=cfg.browser.scroll,
            ignore_system_proxy=cfg.browser.ignore_system_proxy,
            visits_per_browser=cfg.browser.visits_per_browser,
            logger=logger,
        )
        self._signals_installed = False

    # ------------------------------------------------------------------ #
    # 状态与种子
    # ------------------------------------------------------------------ #
    def _load_state(self) -> Dict[str, Any]:
        if not os.path.exists(self.state_path):
            return {}
        try:
            with open(self.state_path, "r", encoding="utf-8") as handle:
                state = json.load(handle)
            if not isinstance(state, dict):
                raise ValueError("状态文件根节点不是对象")
            self.logger.info("已加载上次状态: %s", self.state_path)
            return state
        except (OSError, ValueError) as exc:
            self.logger.warning("状态文件无法读取（%s），将从零开始: %s", exc, self.state_path)
            return {}

    def _resolve_seed(self) -> tuple:
        """种子优先级：命令行/配置 > 状态文件 > 自动生成。"""
        if self.cfg.vps.seed is not None:
            return int(self.cfg.vps.seed), "config"
        saved = self.state.get("seed")
        if saved is not None:
            return int(saved), "state"
        return random.SystemRandom().randrange(1, 2**31 - 1), "generated"

    def _save_state(self) -> None:
        payload = {
            "seed": self.seed,
            "seed_source": self.seed_source,
            "vps": self.cfg.vps.name,
            "saved_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "scheduler": self.scheduler.snapshot(),
        }
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        tmp_path = self.state_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        os.replace(tmp_path, self.state_path)

    # ------------------------------------------------------------------ #
    # 运行
    # ------------------------------------------------------------------ #
    def _install_signal_handlers(self) -> None:
        def handler(signum, _frame):
            if not self.stop_event.is_set():
                self.logger.info("收到信号 %s，将在当前访问结束后退出", signum)
            self.stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, handler)
            except ValueError:  # 非主线程（例如被当作库调用）
                self.logger.debug("无法在主线程外注册信号 %s", sig)
        self._signals_installed = True

    def run(self) -> Dict[str, Any]:
        """运行主循环，返回汇总字典。"""
        started_wall = datetime.now().astimezone()
        started_mono = time.monotonic()
        self._install_signal_handlers()
        self._log_startup()

        if not self.cfg.dry_run:
            try:
                mode = ensure_direct_transport()
                self.logger.info("传输模式校验通过：SPIDER_MODE=%s", mode)
            except BrowserError as exc:
                self.logger.error("启动前检查失败：%s", exc)
                return {"ok": False, "error": str(exc)}
            kill_orphan_browsers(self.cfg.browser.name, self.logger)

        try:
            self.capture.start()
        except CaptureError as exc:
            self.logger.error("抓包启动失败：%s", exc)
            return {"ok": False, "error": str(exc)}

        failures = 0
        writer = GroundTruthWriter(self.cfg.storage.groundtruth_file, self.logger)
        try:
            while not self.stop_event.is_set():
                if self._visit_limit_reached():
                    break
                record = self._run_single_visit()
                writer.write(record)
                self._save_state()
                if not record.success:
                    failures += 1
                if self.scheduler.visits_total % self.cfg.log_every == 0:
                    self._log_progress()
                if self._visit_limit_reached():
                    break
                if not self._sleep_between_visits():
                    break
        finally:
            writer.close()
            if self.browser is not None:
                self.browser.close()
            self.capture.stop()

        summary = self._build_summary(started_wall, started_mono, failures)
        self._log_summary(summary)
        return summary

    # ------------------------------------------------------------------ #
    # 单次访问
    # ------------------------------------------------------------------ #
    def _run_single_visit(self) -> VisitRecord:
        self.capture.maybe_rotate()
        pcap_before = self.capture.current_file

        choice = self.scheduler.next_choice()
        url = f"https://{choice.site}"
        keylog_file = self.capture.keylog_path() if self.capture.enabled else None
        if keylog_file:
            # 浏览器（chrome/edge/firefox）在启动时读取该环境变量
            os.environ["SSLKEYLOGFILE"] = keylog_file

        start_dt = datetime.now().astimezone()
        start_mono = time.monotonic()
        outcome: Dict[str, Any] = {}
        error: Optional[str] = None
        error_type: Optional[str] = None

        if self.cfg.dry_run:
            time.sleep(0.01)
        else:
            try:
                outcome = self.browser.visit(url)
            except Exception as exc:  # 单次失败不影响连续运行
                error = str(exc)
                error_type = type(exc).__name__
                self.logger.warning("访问失败 %s：%s", url, exc)

        duration = time.monotonic() - start_mono
        end_dt = datetime.now().astimezone()
        observed_ratio = self.scheduler.stats()["observed_ratio"]
        record = VisitRecord(
            visit_index=self.scheduler.visits_total,
            vps=self.cfg.vps.name,
            site=choice.site,
            url=url,
            category=choice.category,
            start_time=start_dt.isoformat(timespec="milliseconds"),
            end_time=end_dt.isoformat(timespec="milliseconds"),
            duration_seconds=round(duration, 3),
            success=error is None,
            error=error,
            error_type=error_type,
            landed_url=outcome.get("landed_url"),
            page_title=outcome.get("page_title"),
            browser=self.cfg.browser.name,
            browser_session_id=outcome.get("browser_session_id"),
            visit_in_session=outcome.get("visit_in_session"),
            pcap_file=pcap_before,
            pcap_file_at_end=self.capture.current_file,
            keylog_file=keylog_file,
            monitored_ratio_target=self.scheduler.ratio,
            monitored_ratio_observed=round(observed_ratio, 6),
            dry_run=self.cfg.dry_run,
        )
        self.logger.info(
            "[%d/%s] %s %s 成功=%s 耗时=%.2fs 会话#%s(第%s次)%s",
            record.visit_index,
            self.cfg.vps.name,
            choice.category,
            choice.site,
            record.success,
            record.duration_seconds,
            record.browser_session_id,
            record.visit_in_session,
            "" if error is None else f" 错误={error_type}",
        )
        return record

    def _sleep_between_visits(self) -> bool:
        seconds = self.sampler.sample()
        self.logger.info("随机间隔 %.1fs（%s）", seconds, self.sampler.describe())
        if not interruptible_sleep(seconds, self.stop_event):
            self.logger.info("等待被中断，准备退出")
            return False
        return True

    # ------------------------------------------------------------------ #
    # 日志与汇总
    # ------------------------------------------------------------------ #
    def _visit_limit_reached(self) -> bool:
        return bool(self.cfg.max_visits) and self.scheduler.visits_total >= self.cfg.max_visits

    def _log_startup(self) -> None:
        cfg = self.cfg
        self.logger.info("=" * 72)
        self.logger.info("Continuous Collection 启动")
        self.logger.info("  配置文件    : %s", cfg.source_path)
        self.logger.info("  VPS         : %s（site=%s）", cfg.vps.name, cfg.vps.site)
        self.logger.info("  随机种子    : %s（来源: %s）", self.seed, self.seed_source)
        self.logger.info(
            "  站点        : monitored %d 个 / background %d 个",
            len(cfg.monitored),
            len(cfg.background),
        )
        self.logger.info(
            "  混合比例    : %.4f（%.2f%%），ratio_mode=%s，background_sampling=%s",
            cfg.sites.monitored_ratio,
            cfg.sites.monitored_ratio * 100,
            cfg.sites.ratio_mode,
            cfg.sites.background_sampling,
        )
        self.logger.info(
            "  访问间隔    : %s，截断后理论均值 %.2fs",
            self.sampler.describe(),
            self.sampler.theoretical_mean(),
        )
        self.logger.info(
            "  浏览器复用  : 每 %d 次访问重启一次（同一会话内复用同一标签页）%s",
            cfg.browser.visits_per_browser,
            "；dry-run 不启动浏览器" if cfg.dry_run else "",
        )
        self.logger.info(
            "  抓包        : enabled=%s filter=%r rotate=%ss → %s",
            self.capture.enabled,
            self.capture.cfg.filter_expression,
            self.capture.cfg.rotate_seconds,
            self.capture.cfg.output_dir,
        )
        self.logger.info("  keylog      : %s", self.capture.cfg.keylog_dir)
        self.logger.info("  groundtruth : %s", cfg.storage.groundtruth_file)
        self.logger.info("  状态文件    : %s", self.state_path)
        self.logger.info(
            "  访问上限    : %s",
            cfg.max_visits if cfg.max_visits else "不限（持续运行）",
        )
        if cfg.dry_run:
            self.logger.info("  模式        : dry-run（不启动浏览器、不抓包）")
        if not self.project_logger_ok:
            self.logger.warning(
                "项目日志不可写：dry-run 可用，但真实访问会因浏览器模块导入失败而报错；"
                '请先执行 sudo chown -R "$USER" logs data'
            )
        self.logger.info("=" * 72)

    def _log_progress(self) -> None:
        stats = self.scheduler.stats()
        self.logger.info(
            "进度：访问 %d 次（monitored %d / background %d，实际比例 %.2f%%，目标 %.2f%%）| "
            "monitored 次数区间 [%d, %d] | background 轮次 #%d",
            stats["visits_total"],
            stats["monitored_visits"],
            stats["background_visits"],
            stats["observed_ratio"] * 100,
            stats["target_ratio"] * 100,
            stats["monitored_count_min"],
            stats["monitored_count_max"],
            stats["background_cycle_index"],
        )

    def _build_summary(
        self, started_wall: datetime, started_mono: float, failures: int
    ) -> Dict[str, Any]:
        stats = self.scheduler.stats()
        return {
            "ok": True,
            "vps": self.cfg.vps.name,
            "seed": self.seed,
            "seed_source": self.seed_source,
            "dry_run": self.cfg.dry_run,
            "started_at": started_wall.isoformat(timespec="seconds"),
            "elapsed_seconds": round(time.monotonic() - started_mono, 3),
            "visits_total": stats["visits_total"],
            "successes": stats["visits_total"] - failures,
            "failures": failures,
            "monitored_visits": stats["monitored_visits"],
            "background_visits": stats["background_visits"],
            "target_ratio": stats["target_ratio"],
            "observed_ratio": round(stats["observed_ratio"], 6),
            "monitored_count_min": stats["monitored_count_min"],
            "monitored_count_max": stats["monitored_count_max"],
            "monitored_spread": stats["monitored_spread"],
            "background_cycle_index": stats["background_cycle_index"],
            "sleep": self.sampler.stats.to_dict(),
            "browser_visits_per_browser": self.cfg.browser.visits_per_browser,
            "browser_launches": (
                self.browser.browser_launches if self.browser is not None else 0
            ),
            "capture_files": [
                {"path": path, "bytes": size} for path, size in self.capture.files_with_size()
            ],
            "groundtruth_file": self.cfg.storage.groundtruth_file,
            "state_file": self.state_path,
        }

    def _log_summary(self, summary: Dict[str, Any]) -> None:
        self.logger.info("-" * 72)
        self.logger.info(
            "结束：访问 %s 次（成功 %s / 失败 %s），monitored %s / background %s，"
            "实际比例 %.2f%%（目标 %.2f%%）",
            summary["visits_total"],
            summary["successes"],
            summary["failures"],
            summary["monitored_visits"],
            summary["background_visits"],
            summary["observed_ratio"] * 100,
            summary["target_ratio"] * 100,
        )
        self.logger.info(
            "monitored 均衡性：每站最少 %s 次 / 最多 %s 次（差 %s）",
            summary["monitored_count_min"],
            summary["monitored_count_max"],
            summary["monitored_spread"],
        )
        sleep_stats = summary["sleep"]
        if sleep_stats["count"]:
            self.logger.info(
                "间隔采样：%d 次，均值 %.2fs，最小 %.2fs，最大 %.2fs",
                sleep_stats["count"],
                sleep_stats["mean_seconds"],
                sleep_stats["min_seconds"],
                sleep_stats["max_seconds"],
            )
        if not summary["dry_run"]:
            self.logger.info(
                "浏览器：共启动 %s 个会话（策略：每 %s 次访问重启一次）",
                summary["browser_launches"],
                summary["browser_visits_per_browser"],
            )
        for item in summary["capture_files"]:
            self.logger.info("pcap: %s（%.1f KiB）", item["path"], item["bytes"] / 1024.0)
        self.logger.info("ground truth: %s", summary["groundtruth_file"])
        self.logger.info("-" * 72)


# --------------------------------------------------------------------------- #
# 命令行
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m spider_traffic.continuous",
        description="Continuous Collection：无 Scrapy 的连续流量采集（第一阶段：HTTPS 直连）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  1) 先验证调度与日志（不抓包、不开浏览器）\n"
            "     python -m spider_traffic.continuous --dry-run --max-visits 50\n"
            "  2) 正式连续采集\n"
            "     python -m spider_traffic.continuous --config ../config/continuous.yaml\n"
        ),
    )
    parser.add_argument(
        "--config",
        default=None,
        help=f"YAML 配置路径（默认 <repo>/config/{DEFAULT_CONFIG_NAME}，"
        f"当前为 {default_config_path()}）",
    )
    parser.add_argument("--max-visits", type=int, default=None,
                        help="访问次数上限（覆盖 YAML；0 表示不限）")
    parser.add_argument("--seed", type=int, default=None, help="随机种子（覆盖 YAML，便于复现）")
    parser.add_argument("--vps", default=None, help="VPS 名称（覆盖 YAML）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只跑调度与 ground truth，不启动浏览器也不抓包")
    parser.add_argument("--print-config", action="store_true", help="打印解析后的配置并退出")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="日志级别")
    return parser


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    logger, project_logger_ok = get_logger(args.log_level)

    try:
        cfg = load_config(
            args.config,
            dry_run=args.dry_run,
            max_visits=args.max_visits,
            seed=args.seed,
            vps_name=args.vps,
        )
    except ConfigError as exc:
        logger.error("配置错误：%s", exc)
        return 2

    if args.print_config:
        print(json.dumps(cfg.summary(), ensure_ascii=False, indent=2))
        return 0

    collector = ContinuousCollector(cfg, logger, project_logger_ok=project_logger_ok)
    summary = collector.run()
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
