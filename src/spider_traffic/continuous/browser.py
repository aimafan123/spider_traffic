"""浏览器生命周期管理：直接复用现有 ``spider/`` 下的浏览器创建逻辑。

被复用的现有函数（不做任何修改）：

- ``spider/chrome.py::create_chrome_driver`` / ``scroll_to_bottom``
- ``spider/edge.py::create_edge_driver``
- ``spider/firefox.py::create_firefox_driver``
- ``spider/__init__.py::kill_browsers``

生命周期策略（``browser.visits_per_browser``）：

- **默认 20**：同一个浏览器进程连续服务 20 次访问，之后才关闭并重开；
- 同一会话内**复用同一个标签页**依次 ``get`` 每个 URL，并在每次访问前关闭页面弹出的
  多余标签页；cookie/缓存等 profile 状态在该会话内共享；
- ``visits_per_browser = 1`` 退化为旧的「每次访问新建并关闭」行为；
- 任何非「页面加载超时」的异常都会把浏览器标记为不可用，下一次访问自动重建。

有意保留的耦合（也是不修改现有流程的代价）：

- 这三个创建函数内部仍然读取 ``config/config.ini`` 与 ``SPIDER_MODE``，
  因此 ``disable_quic``、``scroll_num``、代理等**浏览器级开关仍由 config.ini 决定**；
- HTTPS 直连模式要求 ``config.ini`` 中 ``mode=direct``，否则浏览器会走 xray/tor 代理，
  与 ``capture.filter_expression = "tcp port 443"`` 的直连抓包不匹配，启动时会直接报错。
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

BROWSER_NAMES = ("chrome", "edge", "firefox")

DEFAULT_VISITS_PER_BROWSER = 20

_REUSE_CACHE: Optional[Dict[str, Any]] = None


class BrowserError(RuntimeError):
    """浏览器无法创建或使用。"""


# --------------------------------------------------------------------------- #
# 现有模块的懒加载（避免 import 期就依赖 selenium 与 logs/ 可写）
# --------------------------------------------------------------------------- #
def _load_reused_code() -> Dict[str, Any]:
    try:
        from spider_traffic.spider import kill_browsers
        from spider_traffic.spider.chrome import create_chrome_driver, scroll_to_bottom
        from spider_traffic.spider.edge import create_edge_driver
        from spider_traffic.spider.firefox import create_firefox_driver
    except Exception as exc:  # pragma: no cover - 取决于运行环境
        raise BrowserError(
            "无法导入现有浏览器模块。常见原因是 logs/ 目录不可写导致导入期抛错，"
            '请先执行： sudo chown -R "$USER" logs data。'
            f"原始错误: {exc}"
        ) from exc
    return {
        "creators": {
            "chrome": create_chrome_driver,
            "edge": create_edge_driver,
            "firefox": create_firefox_driver,
        },
        "kill_browsers": kill_browsers,
        "scroll_to_bottom": scroll_to_bottom,
    }


def _reused() -> Dict[str, Any]:
    global _REUSE_CACHE
    if _REUSE_CACHE is None:
        _REUSE_CACHE = _load_reused_code()
    return _REUSE_CACHE


def current_spider_mode() -> str:
    """返回 ``config/config.ini`` 中的 ``[spider] mode``。"""
    try:
        from spider_traffic.myutils.config import SPIDER_MODE
    except Exception as exc:
        raise BrowserError(
            f"无法读取 config/config.ini 的 [spider] mode：{exc}"
        ) from exc
    return str(SPIDER_MODE).strip().lower()


def ensure_direct_transport() -> str:
    """校验当前为直连模式；连续采集第一阶段只支持 HTTPS 直连。"""
    mode = current_spider_mode()
    if mode != "direct":
        raise BrowserError(
            f"continuous HTTPS 模式要求 config/config.ini 中 [spider] mode=direct，"
            f"当前为 {mode!r}。xray/tor 模式下浏览器会走代理，"
            f"与连续抓包的 `tcp port 443` 直连过滤不匹配。"
        )
    return mode


def kill_orphan_browsers(browser_name: str, logger) -> None:
    """复现单 trace 流程的收尾方式：按浏览器类型清理残留进程。"""
    try:
        _reused()["kill_browsers"](browser_name)
        logger.info("已清理残留的 %s 进程", browser_name)
    except Exception as exc:  # pragma: no cover - 清理失败不应中断主流程
        logger.warning("清理 %s 进程失败: %s", browser_name, exc)


# Firefox 默认 `network.proxy.type = 5`（使用系统代理），在 Linux 上会读取这些环境变量。
# 若宿主机（如本机）把 http_proxy/https_proxy 指向本地 xray，浏览器就会走隧道：
# 抓包里只有到代理服务器的 TLS，目标站点的 SNI 根本不会出现。
_PROXY_ENV_KEYS = (
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
)


def disable_system_proxy_env(logger) -> List[str]:
    """直连采集前移除代理环境变量，返回被移除的变量名。"""
    removed = [key for key in _PROXY_ENV_KEYS if key in os.environ]
    for key in removed:
        os.environ.pop(key, None)
    if removed:
        logger.info("已忽略系统代理环境变量（保证直连）: %s", ", ".join(removed))
    return removed


def create_browser(browser_name: str, logger):
    """调用现有创建函数创建 WebDriver（统一处理可能返回的 (driver, path) 元组）。"""
    if browser_name not in BROWSER_NAMES:
        raise BrowserError(f"不支持的浏览器 {browser_name!r}，可选 {BROWSER_NAMES}")
    ensure_direct_transport()
    creator = _reused()["creators"][browser_name]
    logger.debug("创建 %s 浏览器", browser_name)
    driver = creator()
    if isinstance(driver, tuple):
        driver = driver[0]
    return driver


def _is_page_level_error(exc: BaseException) -> bool:
    """页面加载超时等错误不影响浏览器继续使用，无需重建。"""
    return type(exc).__name__ == "TimeoutException"


class BrowserSessionManager:
    """跨访问复用浏览器进程，每 ``visits_per_browser`` 次访问重启一次。

    Args:
        browser_name: ``chrome`` / ``edge`` / ``firefox``。
        settle_seconds: 页面加载后的额外停留。
        page_load_timeout: 单页加载超时。
        scroll: 是否滚动页面（滚动次数沿用 config.ini 的 ``scroll_num``）。
        ignore_system_proxy: 创建浏览器前是否移除代理环境变量。
        visits_per_browser: 每个浏览器会话最多服务多少次访问，``1`` 表示每次重建。
        logger: 注入的 logger。
    """

    def __init__(
        self,
        browser_name: str,
        settle_seconds: float,
        page_load_timeout: float,
        scroll: bool,
        ignore_system_proxy: bool,
        visits_per_browser: int,
        logger,
    ) -> None:
        self.browser_name = browser_name
        self.settle_seconds = float(settle_seconds)
        self.page_load_timeout = float(page_load_timeout)
        self.scroll = bool(scroll)
        self.ignore_system_proxy = bool(ignore_system_proxy)
        self.visits_per_browser = max(int(visits_per_browser), 1)
        self.logger = logger

        self._driver = None
        self._session_id = 0          # 第几个浏览器会话（从 1 开始）
        self._visits_in_session = 0   # 当前会话已服务的访问次数
        self._session_started = False  # 当前会话是否已经开始（用于首访标记）
        self.browser_launches = 0     # 累计启动次数（用于汇总/校验）

    # ------------------------------------------------------------------ #
    # 只读属性（供 ground truth 记录）
    # ------------------------------------------------------------------ #
    @property
    def session_id(self) -> int:
        return self._session_id

    @property
    def visits_in_session(self) -> int:
        return self._visits_in_session

    # ------------------------------------------------------------------ #
    # 对外接口
    # ------------------------------------------------------------------ #
    def visit(self, url: str) -> Dict[str, Any]:
        """访问一个 URL；必要时（首次 / 达到上限 / 上次异常）先重建浏览器。"""
        self._ensure_browser()
        self._prepare_tab()
        self._visits_in_session += 1
        visit_no = self._visits_in_session
        try:
            outcome = self._load(url)
        except Exception as exc:
            if _is_page_level_error(exc):
                self.logger.info(
                    "页面加载超时（浏览器会话 #%d 继续使用）: %s", self._session_id, url
                )
            else:
                self._teardown(f"访问异常 {type(exc).__name__}，下次访问重建")
            raise
        outcome["browser_session_id"] = self._session_id
        outcome["visit_in_session"] = visit_no
        return outcome

    def close(self) -> None:
        """结束运行：关闭当前浏览器会话。"""
        if self._driver is not None:
            self._teardown("运行结束")

    # ------------------------------------------------------------------ #
    # 内部实现
    # ------------------------------------------------------------------ #
    def _ensure_browser(self) -> None:
        if self._driver is not None and self._visits_in_session < self.visits_per_browser:
            return
        if self._driver is not None:
            self.logger.info(
                "会话 #%d 已服务 %d 次访问（达到 visits_per_browser=%d），重启浏览器",
                self._session_id,
                self._visits_in_session,
                self.visits_per_browser,
            )
            self._teardown("达到会话访问上限")
        self._launch()

    def _launch(self) -> None:
        if self.ignore_system_proxy:
            disable_system_proxy_env(self.logger)
        self._driver = create_browser(self.browser_name, self.logger)
        self._session_id += 1
        self._visits_in_session = 0
        self._session_started = False
        self.browser_launches += 1
        self.logger.info(
            "创建浏览器会话 #%d（本会话最多服务 %d 次访问）",
            self._session_id,
            self.visits_per_browser,
        )

    def _teardown(self, reason: str) -> None:
        driver, self._driver = self._driver, None
        self._session_started = False
        if driver is None:
            return
        try:
            driver.quit()
            self.logger.info("关闭浏览器会话 #%d（%s）", self._session_id, reason)
        except Exception as exc:
            self.logger.warning("driver.quit() 失败（%s），回退到 pkill 清理", exc)
            kill_orphan_browsers(self.browser_name, self.logger)

    def _prepare_tab(self) -> None:
        """同一会话内复用同一个标签页（不新开标签页），只清理页面弹出的多余标签页。

        为什么不再「每次访问新开标签页」：Selenium 的 ``switch_to.new_window("tab")``
        会加载 Chrome 的新标签页，而该页面会触发一批 Google 服务请求
        （实测新增 ``cse.google.com`` / ``syndicatedsearch.goog`` /
        ``adsensecustomsearchads.com`` 等与目标站点无关的连接）。
        由于同一浏览器会话内 cookie/缓存本来就是共享的，复用标签页既没有损失，
        又能显著降低测量噪声；测量语义与单 trace 流程一致（同一个标签页依次 ``get``）。
        """
        if not self._session_started:
            self._session_started = True
        self._close_other_tabs()

    def _close_other_tabs(self) -> None:
        driver = self._driver
        try:
            handles = driver.window_handles
            if len(handles) <= 1:
                return
            current = driver.current_window_handle
        except Exception:  # pragma: no cover - 取句柄失败时保持现状
            return
        for handle in handles:
            if handle == current:
                continue
            try:
                driver.switch_to.window(handle)
                driver.close()
            except Exception:  # pragma: no cover
                pass
        try:
            driver.switch_to.window(current)
        except Exception:  # pragma: no cover
            pass

    def _load(self, url: str) -> Dict[str, Any]:
        driver = self._driver
        driver.set_page_load_timeout(self.page_load_timeout)
        driver.get(url)
        if self.scroll:
            _reused()["scroll_to_bottom"](driver)
        if self.settle_seconds > 0:
            time.sleep(self.settle_seconds)

        landed_url: Optional[str] = None
        page_title: Optional[str] = None
        try:
            landed_url = driver.current_url
        except Exception:  # pragma: no cover - 取不到不影响样本判定
            pass
        try:
            page_title = driver.title
        except Exception:  # pragma: no cover
            pass
        return {"landed_url": landed_url, "page_title": page_title}
