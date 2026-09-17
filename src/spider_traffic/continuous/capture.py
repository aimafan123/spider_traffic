"""连续抓包：单个 tcpdump 进程持续抓包，并按时间桶（默认小时）切分 pcap。

为什么没有直接调用 ``traffic/capture.py::capture()``：

- 现有 ``capture()`` 与 ``SPIDER_MODE`` 绑定（xray 模式会追加 ``host`` 过滤），一次调用
  只产出**一个**文件，且不提供轮转与错误可见性；
- 连续采集需要「长跑 + 按时间桶切分 + stderr 落盘可诊断」，这些能力无法在不修改现有
  单 trace 流程的前提下复用。

因此这里沿用它的一套约定（tcpdump 参数风格、终止时 terminate→超时→kill 的收尾顺序），
但独立实现生命周期管理。
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from datetime import datetime
from typing import List, Optional, Tuple

from spider_traffic.continuous.config import CaptureConfig


class CaptureError(RuntimeError):
    """抓包无法启动或异常退出。"""


_TOKEN_RE = re.compile(r"[^0-9A-Za-z._-]+")


def safe_token(value: str) -> str:
    """把任意字符串转成可用于文件名的 token。"""
    return _TOKEN_RE.sub("_", value.strip()) or "vps"


class HourlyPcapCapture:
    """长期运行的抓包进程，按时间桶轮转输出文件。

    Args:
        cfg: 抓包配置（已解析为绝对路径）。
        vps_name: VPS 名称，用于文件名。
        logger: 注入的 logger。
    """

    def __init__(self, cfg: CaptureConfig, vps_name: str, logger) -> None:
        self.cfg = cfg
        self.vps_name = vps_name
        self.logger = logger
        self._process: Optional[subprocess.Popen] = None
        self._stderr_handle = None
        self._current_file: Optional[str] = None
        self._current_bucket: Optional[datetime] = None
        self._rotate_seconds = max(int(cfg.rotate_seconds), 1)

    # ------------------------------------------------------------------ #
    # 属性
    # ------------------------------------------------------------------ #
    @property
    def enabled(self) -> bool:
        return bool(self.cfg.enabled)

    @property
    def current_file(self) -> Optional[str]:
        """当前正在写入的 pcap 路径（未启动或已禁用时为 None）。"""
        return self._current_file

    @property
    def started_files(self) -> List[str]:
        """本次运行启动过的所有 pcap 路径。"""
        return list(getattr(self, "_started_files", []))

    def files_with_size(self) -> List[Tuple[str, int]]:
        """返回已产出文件及其大小（字节），用于结束统计。"""
        result: List[Tuple[str, int]] = []
        for path in getattr(self, "_started_files", []):
            try:
                result.append((path, os.path.getsize(path)))
            except OSError:
                result.append((path, -1))
        return result

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def start(self) -> Optional[str]:
        """启动抓包；返回当前 pcap 路径。"""
        self._started_files: List[str] = []
        if not self.enabled:
            self.logger.info("抓包已禁用（capture.enabled=false 或 --dry-run），跳过 tcpdump")
            return None
        self._ensure_dirs()
        try:
            self._stderr_handle = open(self.cfg.stderr_log, "ab")
        except OSError as exc:
            raise CaptureError(f"无法写入 tcpdump 日志 {self.cfg.stderr_log}: {exc}") from exc
        self._start_process()
        return self._current_file

    def maybe_rotate(self, now: Optional[float] = None) -> Optional[str]:
        """若已跨入新的时间桶则切分文件；返回当前 pcap 路径。"""
        if not self.enabled:
            return None
        bucket = self._bucket_start(now)
        if self._process is None:
            self._start_process(now)
            return self._current_file
        if self._current_bucket != bucket:
            self.logger.info(
                "pcap 轮转：%s → %s",
                self._current_bucket.strftime("%Y-%m-%d %H:%M:%S"),
                bucket.strftime("%Y-%m-%d %H:%M:%S"),
            )
            self._stop_process()
            self._start_process(now)
        return self._current_file

    def stop(self) -> None:
        """停止抓包并关闭 stderr 日志。"""
        if self._process is not None:
            self._stop_process()
        if self._stderr_handle is not None:
            try:
                self._stderr_handle.close()
            except OSError:
                pass
            self._stderr_handle = None

    def keylog_path(self, now: Optional[float] = None) -> str:
        """当前时间桶对应的 TLS keylog 路径（与 pcap 同桶，便于离线解码）。"""
        bucket = self._bucket_start(now)
        filename = f"sslkeys_{safe_token(self.vps_name)}_{bucket:%Y%m%d_%H%M%S}.log"
        return os.path.join(self.cfg.keylog_dir, filename)

    # ------------------------------------------------------------------ #
    # 内部实现
    # ------------------------------------------------------------------ #
    def _ensure_dirs(self) -> None:
        for directory in (
            self.cfg.output_dir,
            self.cfg.keylog_dir,
            os.path.dirname(self.cfg.stderr_log),
        ):
            if directory:
                os.makedirs(directory, exist_ok=True)

    def _bucket_start(self, now: Optional[float] = None) -> datetime:
        """当前时间所属时间桶的起点（默认 3600 秒 → 整点）。"""
        timestamp = int(time.time() if now is None else now)
        return datetime.fromtimestamp(timestamp - (timestamp % self._rotate_seconds))

    def _path_for(self, bucket: datetime) -> str:
        filename = (
            f"{self.cfg.prefix}_{safe_token(self.vps_name)}_{bucket:%Y%m%d_%H%M%S}.pcap"
        )
        return os.path.join(self.cfg.output_dir, filename)

    def _expression(self) -> str:
        expression = self.cfg.filter_expression.strip()
        for port in self.cfg.exclude_ports:
            clause = f"not port {int(port)}"
            expression = f"({expression}) and {clause}" if expression else clause
        return expression

    def _build_command(self, path: str) -> List[str]:
        """构造 tcpdump 命令；过滤器必须放在所有选项之后。"""
        command: List[str] = [self.cfg.tcpdump_binary, "-n"]
        if self.cfg.interface:
            command += ["-i", self.cfg.interface]
        if self.cfg.snaplen is not None:
            command += ["-s", str(int(self.cfg.snaplen))]
        command += list(self.cfg.extra_args)
        command += ["-w", path]
        expression = self._expression()
        if expression:
            command.append(expression)
        return command

    def _start_process(self, now: Optional[float] = None) -> None:
        bucket = self._bucket_start(now)
        path = self._path_for(bucket)
        command = self._build_command(path)
        self.logger.info("启动抓包: %s", " ".join(command))
        try:
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=self._stderr_handle,
            )
        except FileNotFoundError as exc:
            raise CaptureError(
                f"未找到抓包程序 {self.cfg.tcpdump_binary!r}；请先安装 tcpdump"
            ) from exc
        except OSError as exc:
            raise CaptureError(f"启动抓包失败: {exc}") from exc

        # tcpdump 因权限不足会立刻退出；这里主动探测，避免"抓了个空文件还不报错"
        time.sleep(0.5)
        if self._process.poll() is not None:
            code = self._process.returncode
            tail = self._read_stderr_tail()
            self._process = None
            raise CaptureError(
                f"tcpdump 立即退出（exit={code}）。请检查抓包权限：\n"
                f"  sudo setcap cap_net_raw,cap_net_admin+eip \"$(which tcpdump)\"\n"
                f"或使用容器 --privileged 运行。tcpdump stderr: {tail}"
            )

        self._current_file = path
        self._current_bucket = bucket
        self._started_files.append(path)
        self.logger.info("抓包进行中（pid=%s）→ %s", self._process.pid, path)

    def _stop_process(self) -> None:
        process, self._process = self._process, None
        if process is None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
            self.logger.info("抓包进程优雅退出（pid=%s）", process.pid)
        except subprocess.TimeoutExpired:
            process.kill()
            self.logger.warning("抓包进程超时未退出，已强制终止（pid=%s）", process.pid)
        if self._current_file:
            self._log_file_size(self._current_file)
        self._current_file = None
        self._current_bucket = None

    def _log_file_size(self, path: str) -> None:
        try:
            size = os.path.getsize(path)
        except OSError:
            self.logger.warning("pcap 文件不存在或不可读: %s", path)
            return
        self.logger.info("pcap 已关闭: %s（%.1f KiB）", path, size / 1024.0)

    def _read_stderr_tail(self, max_bytes: int = 2000) -> str:
        if not self.cfg.stderr_log or not os.path.exists(self.cfg.stderr_log):
            return ""
        try:
            with open(self.cfg.stderr_log, "rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(size - max_bytes, 0))
                return handle.read().decode("utf-8", errors="replace").strip()
        except OSError:
            return ""
