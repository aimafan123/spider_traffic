"""Continuous Collection 的 YAML 配置加载与校验。

约定：

- **YAML 内部**的相对路径一律相对**仓库根目录**解析（复用 ``myutils.project_path``），因此在任意
  工作目录下运行结果一致；``--config`` 传入的路径则先按当前工作目录、再按仓库根目录尝试；
- 本模块只读 YAML，既不读取也不修改 ``config/config.ini``，避免影响现有单 trace 流程；
- 站点列表支持纯主机名，也容忍 ``https://example.com/`` 这类写法（会自动归一化）。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from spider_traffic.myutils import project_path

SUPPORTED_BROWSERS = ("chrome", "edge", "firefox")
SUPPORTED_MODES = ("https",)
SUPPORTED_RATIO_MODES = ("bernoulli", "exact")
SUPPORTED_BACKGROUND_SAMPLING = ("shuffled_cycle", "random_choice")
SUPPORTED_SLEEP_DISTRIBUTIONS = ("truncated_exponential",)

DEFAULT_CONFIG_NAME = "continuous.yaml"

_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)


class ConfigError(ValueError):
    """配置缺失或取值非法。"""


@dataclass
class VpsConfig:
    """单个 VPS 的标识与随机种子。"""

    name: str
    site: str = "unknown"
    seed: Optional[int] = None


@dataclass
class BrowserConfig:
    """浏览器选择与单次访问节奏。"""

    name: str = "chrome"
    settle_seconds: float = 3.0
    page_load_timeout: float = 60.0
    scroll: bool = True
    # Firefox 在默认「使用系统代理」下会读取 http_proxy/https_proxy 环境变量；
    # 直连采集必须移除它们，否则浏览器走代理、抓到的将是隧道流量而不是目标站点 TLS。
    ignore_system_proxy: bool = True
    # 一个浏览器进程连续服务多少次访问后才重启（1 = 每次访问都重启，即旧行为）。
    # 同一会话内每次访问使用全新标签页，但 profile（cookie/缓存）在该会话内共享。
    visits_per_browser: int = 20


@dataclass
class SiteConfig:
    """站点列表与混合比例策略。"""

    mode: str = "https"
    monitored_file: str = "config/continuous_monitored.txt"
    background_file: str = "config/continuous_background.txt"
    monitored_ratio: float = 0.05
    ratio_mode: str = "bernoulli"
    background_sampling: str = "shuffled_cycle"


@dataclass
class SleepConfig:
    """访问间隔分布（默认截断指数）。"""

    distribution: str = "truncated_exponential"
    mean_seconds: float = 20.0
    min_seconds: float = 3.0
    max_seconds: float = 90.0


@dataclass
class CaptureConfig:
    """连续抓包与按时间桶切分。"""

    enabled: bool = True
    tcpdump_binary: str = "tcpdump"
    interface: Optional[str] = None
    filter_expression: str = "tcp port 443"
    exclude_ports: List[int] = field(default_factory=list)
    snaplen: Optional[int] = None
    extra_args: List[str] = field(default_factory=list)
    rotate_seconds: int = 3600
    prefix: str = "continuous"
    output_dir: str = "data/continuous/pcap"
    keylog_dir: str = "data/continuous/keylog"
    stderr_log: str = "logs/continuous_tcpdump.log"


@dataclass
class StorageConfig:
    """ground truth 与状态文件位置。"""

    groundtruth_file: str = "data/continuous/ground_truth.jsonl"
    state_dir: str = "data/continuous/state"


@dataclass
class ContinuousConfig:
    """解析并校验后的完整配置。"""

    source_path: str
    vps: VpsConfig
    browser: BrowserConfig
    sites: SiteConfig
    sleep: SleepConfig
    capture: CaptureConfig
    storage: StorageConfig
    max_visits: int = 0
    log_every: int = 10
    dry_run: bool = False
    monitored: List[str] = field(default_factory=list)
    background: List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        """用于日志与 ``--print-config`` 的摘要（不含完整站点列表）。"""
        return {
            "source_path": self.source_path,
            "vps": {"name": self.vps.name, "site": self.vps.site, "seed": self.vps.seed},
            "browser": {
                "name": self.browser.name,
                "settle_seconds": self.browser.settle_seconds,
                "page_load_timeout": self.browser.page_load_timeout,
                "scroll": self.browser.scroll,
                "ignore_system_proxy": self.browser.ignore_system_proxy,
                "visits_per_browser": self.browser.visits_per_browser,
            },
            "sites": {
                "mode": self.sites.mode,
                "monitored_file": self.sites.monitored_file,
                "background_file": self.sites.background_file,
                "monitored_count": len(self.monitored),
                "background_count": len(self.background),
                "monitored_ratio": self.sites.monitored_ratio,
                "ratio_mode": self.sites.ratio_mode,
                "background_sampling": self.sites.background_sampling,
            },
            "sleep": {
                "distribution": self.sleep.distribution,
                "mean_seconds": self.sleep.mean_seconds,
                "min_seconds": self.sleep.min_seconds,
                "max_seconds": self.sleep.max_seconds,
            },
            "capture": {
                "enabled": self.capture.enabled,
                "tcpdump_binary": self.capture.tcpdump_binary,
                "interface": self.capture.interface,
                "filter_expression": self.capture.filter_expression,
                "exclude_ports": list(self.capture.exclude_ports),
                "rotate_seconds": self.capture.rotate_seconds,
                "prefix": self.capture.prefix,
                "output_dir": self.capture.output_dir,
                "keylog_dir": self.capture.keylog_dir,
                "stderr_log": self.capture.stderr_log,
            },
            "storage": {
                "groundtruth_file": self.storage.groundtruth_file,
                "state_dir": self.storage.state_dir,
            },
            "max_visits": self.max_visits,
            "log_every": self.log_every,
            "dry_run": self.dry_run,
        }


# --------------------------------------------------------------------------- #
# 路径与基础解析
# --------------------------------------------------------------------------- #
def resolve_path(path: str) -> str:
    """把**配置内部**的相对路径按仓库根目录解析为绝对路径。"""
    if not path:
        raise ConfigError("路径不能为空")
    if os.path.isabs(path):
        return os.path.normpath(path)
    return os.path.normpath(os.path.join(project_path, path))


def default_config_path() -> str:
    """默认配置文件：``<repo>/config/continuous.yaml``。"""
    return os.path.join(project_path, "config", DEFAULT_CONFIG_NAME)


def _resolve_config_path(path: str) -> str:
    """解析命令行传入的 `--config` 路径。

    与配置内部路径不同，CLI 参数先按**当前工作目录**解析（符合命令行习惯），
    若不存在再回退到**仓库根目录**，因此下面两种写法都能用：

    - 仓库根: ``--config config/continuous.yaml``
    - src 目录: ``--config ../config/continuous.yaml``
    """
    if os.path.isabs(path):
        return os.path.normpath(path)
    candidates = [os.path.abspath(path), os.path.join(project_path, path)]
    for candidate in candidates:
        if os.path.exists(candidate):
            return os.path.normpath(candidate)
    return os.path.normpath(candidates[0])


def _section(data: Dict[str, Any], name: str) -> Dict[str, Any]:
    value = data.get(name) or {}
    if not isinstance(value, dict):
        raise ConfigError(f"配置段 `{name}` 必须是映射（mapping）")
    return value


def _as_bool(value: Any, key: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "yes", "on", "1"):
            return True
        if lowered in ("false", "no", "off", "0"):
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    raise ConfigError(f"`{key}` 需要布尔值，收到 {value!r}")


def parse_ratio(value: Any) -> float:
    """解析比例，支持 ``0.05``、``5%``、``"5%"`` 三种写法。"""
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("%"):
            return float(text[:-1]) / 100.0
        return float(text)
    return float(value)


def _read_sites(path: str, label: str) -> List[str]:
    """读取站点列表：去空行/注释、归一化为纯主机名、保序去重。"""
    if not os.path.exists(path):
        raise ConfigError(f"{label} 列表不存在: {path}")
    sites: List[str] = []
    seen = set()
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            line = _SCHEME_RE.sub("", line)
            host = line.split("/")[0].strip().strip(".")
            if not host or host in seen:
                continue
            seen.add(host)
            sites.append(host)
    if not sites:
        raise ConfigError(f"{label} 列表为空: {path}")
    return sites


# --------------------------------------------------------------------------- #
# 主入口
# --------------------------------------------------------------------------- #
def load_config(
    path: Optional[str] = None,
    *,
    dry_run: bool = False,
    max_visits: Optional[int] = None,
    seed: Optional[int] = None,
    vps_name: Optional[str] = None,
) -> ContinuousConfig:
    """加载 YAML 配置并与命令行覆盖项合并。

    Args:
        path: YAML 路径；``None`` 时使用 ``config/continuous.yaml``。
        dry_run: 命令行 ``--dry-run``，为 True 时强制关闭抓包。
        max_visits: 命令行覆盖的访问次数上限。
        seed: 命令行覆盖的随机种子。
        vps_name: 命令行覆盖的 VPS 名称。

    Returns:
        ContinuousConfig: 已完成路径解析与校验的配置对象。

    Raises:
        ConfigError: 文件不存在、YAML 非法或字段取值不合法。
    """
    config_path = _resolve_config_path(path) if path else default_config_path()
    if not os.path.exists(config_path):
        raise ConfigError(
            f"配置文件不存在: {config_path}\n"
            f"可先复制示例: cp config/{DEFAULT_CONFIG_NAME.replace('.yaml', '.example.yaml')} "
            f"config/{DEFAULT_CONFIG_NAME}"
        )

    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML 解析失败: {config_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"配置根节点必须是映射: {config_path}")

    vps_raw = _section(raw, "vps")
    browser_raw = _section(raw, "browser")
    sites_raw = _section(raw, "sites")
    sleep_raw = _section(raw, "sleep")
    capture_raw = _section(raw, "capture")
    storage_raw = _section(raw, "storage")

    name = str(vps_name or vps_raw.get("name") or "").strip()
    if not name:
        raise ConfigError("`vps.name` 不能为空（每个 VPS 需独立命名，seed/状态/pcap 名都会带上它）")

    cfg = ContinuousConfig(
        source_path=config_path,
        vps=VpsConfig(
            name=name,
            site=str(vps_raw.get("site", "unknown")),
            seed=int(seed) if seed is not None else (
                int(vps_raw["seed"]) if vps_raw.get("seed") is not None else None
            ),
        ),
        browser=BrowserConfig(
            name=str(browser_raw.get("name", "chrome")).strip().lower(),
            settle_seconds=float(browser_raw.get("settle_seconds", 3.0)),
            page_load_timeout=float(browser_raw.get("page_load_timeout", 60.0)),
            scroll=_as_bool(browser_raw.get("scroll", True), "browser.scroll"),
            ignore_system_proxy=_as_bool(
                browser_raw.get("ignore_system_proxy", True),
                "browser.ignore_system_proxy",
            ),
            visits_per_browser=int(
                browser_raw.get("visits_per_browser", 20)
            ),
        ),
        sites=SiteConfig(
            mode=str(sites_raw.get("mode", "https")).strip().lower(),
            monitored_file=resolve_path(str(sites_raw.get(
                "monitored_file", "config/continuous_monitored.txt"))),
            background_file=resolve_path(str(sites_raw.get(
                "background_file", "config/continuous_background.txt"))),
            monitored_ratio=parse_ratio(sites_raw.get("monitored_ratio", 0.05)),
            ratio_mode=str(sites_raw.get("ratio_mode", "bernoulli")).strip().lower(),
            background_sampling=str(
                sites_raw.get("background_sampling", "shuffled_cycle")
            ).strip().lower(),
        ),
        sleep=SleepConfig(
            distribution=str(
                sleep_raw.get("distribution", "truncated_exponential")
            ).strip().lower(),
            mean_seconds=float(sleep_raw.get("mean", 20.0)),
            min_seconds=float(sleep_raw.get("min", 3.0)),
            max_seconds=float(sleep_raw.get("max", 90.0)),
        ),
        capture=CaptureConfig(
            enabled=_as_bool(capture_raw.get("enabled", True), "capture.enabled"),
            tcpdump_binary=str(capture_raw.get("tcpdump_binary", "tcpdump")),
            interface=(
                str(capture_raw["interface"]) if capture_raw.get("interface") else None
            ),
            filter_expression=str(
                capture_raw.get("filter_expression", "tcp port 443")
            ).strip(),
            exclude_ports=[int(port) for port in (capture_raw.get("exclude_ports") or [])],
            snaplen=(
                int(capture_raw["snaplen"])
                if capture_raw.get("snaplen") is not None
                else None
            ),
            extra_args=[str(item) for item in (capture_raw.get("extra_args") or [])],
            rotate_seconds=int(capture_raw.get("rotate_seconds", 3600)),
            prefix=str(capture_raw.get("prefix", "continuous")).strip() or "continuous",
            output_dir=resolve_path(str(
                capture_raw.get("output_dir", "data/continuous/pcap"))),
            keylog_dir=resolve_path(str(
                capture_raw.get("keylog_dir", "data/continuous/keylog"))),
            stderr_log=resolve_path(str(
                capture_raw.get("stderr_log", "logs/continuous_tcpdump.log"))),
        ),
        storage=StorageConfig(
            groundtruth_file=resolve_path(str(storage_raw.get(
                "groundtruth_file", "data/continuous/ground_truth.jsonl"))),
            state_dir=resolve_path(str(
                storage_raw.get("state_dir", "data/continuous/state"))),
        ),
        max_visits=int(max_visits if max_visits is not None else raw.get("max_visits", 0)),
        log_every=max(int(raw.get("log_every", 10)), 1),
        dry_run=bool(dry_run or _as_bool(raw.get("dry_run", False), "dry_run")),
    )

    _validate(cfg)
    cfg.monitored = _read_sites(cfg.sites.monitored_file, "monitored")
    cfg.background = _read_sites(cfg.sites.background_file, "background")
    _validate_site_lists(cfg)
    return cfg


def _validate(cfg: ContinuousConfig) -> None:
    if cfg.sites.mode not in SUPPORTED_MODES:
        raise ConfigError(
            f"第一阶段仅支持 HTTPS 模式，`sites.mode` 必须是 {SUPPORTED_MODES}，"
            f"收到 {cfg.sites.mode!r}"
        )
    if cfg.browser.name not in SUPPORTED_BROWSERS:
        raise ConfigError(
            f"`browser.name` 必须是 {SUPPORTED_BROWSERS} 之一，收到 {cfg.browser.name!r}"
        )
    if not 0.0 < cfg.sites.monitored_ratio <= 1.0:
        raise ConfigError(
            f"`sites.monitored_ratio` 必须在 (0, 1] 内（如 0.05 或 5%），"
            f"收到 {cfg.sites.monitored_ratio}"
        )
    if cfg.sites.ratio_mode not in SUPPORTED_RATIO_MODES:
        raise ConfigError(
            f"`sites.ratio_mode` 必须是 {SUPPORTED_RATIO_MODES} 之一，"
            f"收到 {cfg.sites.ratio_mode!r}"
        )
    if cfg.sites.background_sampling not in SUPPORTED_BACKGROUND_SAMPLING:
        raise ConfigError(
            f"`sites.background_sampling` 必须是 {SUPPORTED_BACKGROUND_SAMPLING} 之一，"
            f"收到 {cfg.sites.background_sampling!r}"
        )
    if cfg.sleep.distribution not in SUPPORTED_SLEEP_DISTRIBUTIONS:
        raise ConfigError(
            f"`sleep.distribution` 必须是 {SUPPORTED_SLEEP_DISTRIBUTIONS} 之一，"
            f"收到 {cfg.sleep.distribution!r}"
        )
    if cfg.sleep.mean_seconds <= 0:
        raise ConfigError("`sleep.mean` 必须 > 0")
    if cfg.sleep.min_seconds < 0:
        raise ConfigError("`sleep.min` 不能为负")
    if cfg.sleep.max_seconds < cfg.sleep.min_seconds:
        raise ConfigError("`sleep.max` 必须 >= `sleep.min`")
    if cfg.capture.rotate_seconds <= 0:
        raise ConfigError("`capture.rotate_seconds` 必须 > 0（3600 表示按小时切分）")
    if cfg.max_visits < 0:
        raise ConfigError("`max_visits` 不能为负（0 表示不限制）")
    if cfg.browser.settle_seconds < 0:
        raise ConfigError("`browser.settle_seconds` 不能为负")
    if cfg.browser.page_load_timeout <= 0:
        raise ConfigError("`browser.page_load_timeout` 必须 > 0")
    if cfg.browser.visits_per_browser < 1:
        raise ConfigError(
            "`browser.visits_per_browser` 必须 >= 1（1 表示每次访问都重启浏览器）"
        )


def _validate_site_lists(cfg: ContinuousConfig) -> None:
    overlap = sorted(set(cfg.monitored) & set(cfg.background))
    if overlap:
        preview = ", ".join(overlap[:5])
        raise ConfigError(
            f"monitored 与 background 列表存在重复站点（{len(overlap)} 个）: {preview}"
        )
