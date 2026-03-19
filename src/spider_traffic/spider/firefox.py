import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

from spider_traffic.myutils import project_path
from spider_traffic.myutils.config import SPIDER_MODE, config

# JavaScript代码：全选并复制页面内容
JS_SELECT_ALL_AND_COPY_CAPTURE = r"""
function __select_all_and_copy_capture(){
  try{
    const sel = window.getSelection();
    const saved = [];
    for (let i=0;i<sel.rangeCount;i++){ saved.push(sel.getRangeAt(i).cloneRange()); }
    function restore(){
      sel.removeAllRanges();
      for (const r of saved) sel.addRange(r);
    }
    sel.removeAllRanges();
    const root = document.body || document.documentElement;
    const range = document.createRange();
    range.selectNodeContents(root);
    sel.addRange(range);

    function selectionPlain(){ return sel.toString(); }
    function selectionHTML(){
      const box = document.createElement('div');
      for (let i=0;i<sel.rangeCount;i++) box.appendChild(sel.getRangeAt(i).cloneContents());
      return box.innerHTML;
    }
    const defaultPlain = selectionPlain();
    const defaultHtml  = selectionHTML();

    let copiedPlain = null, copiedHtml = null;
    function onCopyCapture(e){ /* 预留 */ }
    function onCopyBubble(e){
      try{ copiedHtml  = e.clipboardData.getData('text/html')  || null; }catch(_){}
      try{ copiedPlain = e.clipboardData.getData('text/plain') || null; }catch(_){}
    }
    document.addEventListener('copy', onCopyCapture, true);
    document.addEventListener('copy', onCopyBubble, false);

    let execOk = false;
    try { execOk = document.execCommand('copy'); } catch(_){}

    document.removeEventListener('copy', onCopyCapture, true);
    document.removeEventListener('copy', onCopyBubble, false);
    restore();

    return {
      execOk,
      plain: copiedPlain  != null && copiedPlain  !== '' ? copiedPlain  : defaultPlain,
      html:  copiedHtml   != null && copiedHtml   !== '' ? copiedHtml   : defaultHtml,
      _defaultPlain: defaultPlain,
      _defaultHtml:  defaultHtml
    };
  }catch(e){
    return { error: String(e) };
  }
}
"""


def kill_firefox_processes() -> None:
    """
    结束 Linux 上的 Firefox/GeckoDriver 进程。
    """
    process_names = ("geckodriver", "firefox-esr", "firefox")

    try:
        for process_name in process_names:
            subprocess.run(
                ["pkill", "-KILL", "-x", process_name],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception as e:
        print(f"Error occurred: {e}")


def _resolve_from_candidates(env_keys, executable_names, common_paths):
    """按环境变量、PATH、常见路径顺序查找可执行文件。"""
    for env_key in env_keys:
        candidate = os.environ.get(env_key)
        if candidate and os.path.exists(candidate):
            return candidate

    for executable_name in executable_names:
        candidate = shutil.which(executable_name)
        if candidate:
            return candidate

    for candidate in common_paths:
        if os.path.exists(candidate):
            return candidate

    return None


def _resolve_firefox_binary():
    # 优先真实 Firefox ELF 二进制，避免 /usr/bin/firefox 这类启动脚本被 geckodriver 拒绝。
    preferred_binary_paths = (
        "/snap/firefox/current/usr/lib/firefox/firefox",
        "/usr/lib/firefox/firefox",
        "/usr/lib64/firefox/firefox",
    )
    for candidate in preferred_binary_paths:
        if os.path.exists(candidate):
            return candidate

    resolved = _resolve_from_candidates(
        env_keys=("FIREFOX_BIN", "FIREFOX_BINARY"),
        executable_names=("firefox", "firefox-esr"),
        common_paths=(
            "/usr/bin/firefox",
            "/usr/bin/firefox-esr",
            "/snap/bin/firefox",
        ),
    )
    if resolved in ("/usr/bin/firefox", "/snap/bin/firefox"):
        snap_real_binary = "/snap/firefox/current/usr/lib/firefox/firefox"
        if os.path.exists(snap_real_binary):
            return snap_real_binary
    return resolved


def _resolve_gecko_driver():
    return _resolve_from_candidates(
        env_keys=("GECKODRIVER", "WEBDRIVER_GECKO_DRIVER"),
        executable_names=("geckodriver",),
        common_paths=(
            "/usr/local/bin/geckodriver",
            "/usr/bin/geckodriver",
        ),
    )


def create_firefox_driver(
    task_name=None,
    formatted_time=None,
    parsers=None,
    enable_ssl_key_log=True,
    data_base_dir=None,
):
    """
    创建Firefox浏览器驱动

    Args:
        task_name: 任务名称
        formatted_time: 格式化的时间字符串
        parsers: 解析器名称/前缀
        enable_ssl_key_log: 是否启用SSL密钥日志（默认True）
        data_base_dir: 数据基础目录

    Returns:
        browser: WebDriver实例
        ssl_key_file_path: SSL密钥日志文件路径（当显式生成时返回）
    """
    kill_firefox_processes()

    if data_base_dir is None:
        data_base_dir = project_path

    ssl_key_file_path = None
    if enable_ssl_key_log and task_name and formatted_time:
        current_time = datetime.now()
        current_data = current_time.strftime("%Y%m%d")
        ssl_key_dir = os.path.join(data_base_dir, "ssl_key", current_data)
        os.makedirs(ssl_key_dir, exist_ok=True)
        filename_prefix = f"{parsers}_" if parsers else ""
        ssl_key_file_path = os.path.join(
            ssl_key_dir, f"{filename_prefix}{formatted_time}_{task_name}_ssl_key.log"
        )

    # download 目录
    download_folder = os.path.join(os.getcwd(), "download")
    os.makedirs(download_folder, exist_ok=True)

    # 环境变量设置
    os.environ["SE_OFFLINE"] = "true"
    # Firefox/NSS 的 TLS 密钥日志用环境变量 SSLKEYLOGFILE
    if ssl_key_file_path:
        os.environ["SSLKEYLOGFILE"] = ssl_key_file_path

    _ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9"

    opts = Options()
    firefox_binary = _resolve_firefox_binary()
    if not firefox_binary:
        raise FileNotFoundError("未找到 Firefox 浏览器二进制文件。")
    opts.binary_location = firefox_binary
    opts.add_argument("-headless")
    opts.add_argument("-private")

    # --- 传输层：按配置关闭 HTTP/3/Alt-Svc + 禁 DoH ---
    # opts.set_preference("security.tls.version.min", 4)  # TLS1.3
    # opts.set_preference("security.tls.version.max", 4)
    if config["spider"].get("disable_quic", "false").strip().lower() == "true":
        opts.set_preference("network.http.http3.enabled", False)
        opts.set_preference("network.http.altsvc.enabled", False)
    opts.set_preference("network.trr.mode", 5)  # 禁 DoH
    opts.set_preference("network.trr.uri", "")
    opts.set_preference("security.OCSP.enabled", 0)

    if SPIDER_MODE == "xray":
        proxy_host = config["proxy"]["host"]
        proxy_port = int(config["proxy"]["port"])
        opts.set_preference("network.proxy.type", 1)
        opts.set_preference("network.proxy.http", proxy_host)
        opts.set_preference("network.proxy.http_port", proxy_port)
        opts.set_preference("network.proxy.ssl", proxy_host)
        opts.set_preference("network.proxy.ssl_port", proxy_port)
    elif SPIDER_MODE == "tor":
        proxy_host = config["proxy"]["host"]
        proxy_port = int(config["proxy"]["port"])
        opts.set_preference("network.proxy.type", 1)
        opts.set_preference("network.proxy.socks", proxy_host)
        opts.set_preference("network.proxy.socks_port", proxy_port)
        opts.set_preference("network.proxy.socks_version", 5)
        opts.set_preference("network.proxy.socks_remote_dns", True)

    # --- 降噪：遥测/实验/上报 ---
    opts.set_preference("app.update.enabled", False)
    opts.set_preference("app.update.auto", False)
    opts.set_preference("toolkit.telemetry.unified", False)
    opts.set_preference("toolkit.telemetry.enabled", False)
    opts.set_preference("toolkit.telemetry.server", "")
    opts.set_preference("toolkit.telemetry.archive.enabled", False)
    opts.set_preference("toolkit.telemetry.updatePing.enabled", False)
    opts.set_preference("toolkit.telemetry.firstShutdownPing.enabled", False)
    opts.set_preference("datareporting.healthreport.uploadEnabled", False)
    opts.set_preference("datareporting.policy.dataSubmissionEnabled", False)
    opts.set_preference("app.normandy.enabled", False)
    opts.set_preference("app.normandy.api_url", "")
    opts.set_preference("app.shield.optoutstudies.enabled", False)
    opts.set_preference("browser.discovery.enabled", False)
    opts.set_preference("browser.ping-centre.telemetry", False)
    opts.set_preference("browser.region.network.url", "")
    opts.set_preference("browser.region.update.enabled", False)

    # --- 连通性/门户探测 ---
    opts.set_preference("network.connectivity-service.enabled", False)
    opts.set_preference("network.captive-portal-service.enabled", False)

    # --- 预取/预连接/预测 ---
    opts.set_preference("network.prefetch-next", False)
    opts.set_preference("network.dns.disablePrefetch", True)
    opts.set_preference("network.dns.disablePrefetchFromHTTPS", True)
    opts.set_preference("network.predictor.enabled", False)
    opts.set_preference("network.predictor.enable-prefetch", False)
    opts.set_preference("network.http.speculative-parallel-limit", 0)
    opts.set_preference("browser.urlbar.speculativeConnect.enabled", False)

    # --- Remote Settings ---
    opts.set_preference("services.settings.enabled", False)
    opts.set_preference("services.settings.server", "http://127.0.0.1:65535")
    opts.set_preference("services.settings.poll_interval", 31536000)
    opts.set_preference("security.remote_settings.crlite_filters.enabled", False)
    opts.set_preference("security.remote_settings.intermediates.enabled", False)
    opts.set_preference("services.blocklist.update_enabled", False)
    opts.set_preference("extensions.blocklist.enabled", False)
    opts.set_preference("extensions.getAddons.cache.enabled", False)
    opts.set_preference("extensions.systemAddon.update.enabled", False)
    opts.set_preference("extensions.update.autoUpdateDefault", False)
    opts.set_preference("extensions.update.enabled", False)
    opts.set_preference("extensions.webservice.discoverURL", "http://127.0.0.1:65535")
    opts.set_preference("media.gmp-gmpopenh264.autoupdate", False)
    opts.set_preference("media.gmp-manager.updateEnabled", False)
    opts.set_preference("media.gmp-manager.url", "http://127.0.0.1:65535")
    opts.set_preference("media.gmp-provider.enabled", False)

    # --- 新标签页/首页外呼 ---
    opts.set_preference(
        "browser.newtabpage.activity-stream.feeds.system.topstories", False
    )
    opts.set_preference("browser.newtabpage.activity-stream.feeds.snippets", False)
    opts.set_preference("browser.newtabpage.activity-stream.showSponsored", False)
    opts.set_preference(
        "browser.newtabpage.activity-stream.showSponsoredTopSites", False
    )
    opts.set_preference("browser.newtabpage.activity-stream.telemetry", False)
    opts.set_preference("extensions.pocket.enabled", False)
    opts.set_preference("browser.newtabpage.enabled", False)
    opts.set_preference("browser.startup.page", 0)
    opts.set_preference("browser.startup.homepage", "about:blank")
    opts.set_preference("browser.shell.checkDefaultBrowser", False)
    opts.set_preference("browser.aboutHomeSnippets.updateUrl", "")

    # --- 搜索 / SafeBrowsing / 定位 ---
    opts.set_preference("browser.safebrowsing.downloads.enabled", False)
    opts.set_preference("browser.safebrowsing.downloads.remote.enabled", False)
    opts.set_preference("browser.safebrowsing.malware.enabled", False)
    opts.set_preference("browser.safebrowsing.phishing.enabled", False)
    opts.set_preference("browser.search.suggest.enabled", False)
    opts.set_preference("browser.urlbar.quicksuggest.enabled", False)
    opts.set_preference("browser.urlbar.suggest.searches", False)
    opts.set_preference("geo.enabled", False)
    opts.set_preference("geo.provider.network.url", "")

    # --- 语言 & 下载 ---
    opts.set_preference("intl.accept_languages", _ACCEPT_LANGUAGE)
    opts.set_preference("browser.download.folderList", 2)
    opts.set_preference("browser.download.dir", download_folder)
    opts.set_preference("browser.download.useDownloadDir", True)
    opts.set_preference("browser.download.manager.showWhenStarting", False)
    opts.set_preference(
        "browser.helperApps.neverAsk.saveToDisk",
        "application/octet-stream,application/pdf,text/plain,text/html,application/json",
    )
    opts.set_preference("pdfjs.disabled", True)

    # 创建 WebDriver（geckodriver）
    gecko_driver = _resolve_gecko_driver()
    if not gecko_driver:
        raise FileNotFoundError(
            "未找到 geckodriver。请安装或设置 GECKODRIVER 环境变量。"
        )
    service = Service(executable_path=gecko_driver)
    browser = webdriver.Firefox(service=service, options=opts)
    if ssl_key_file_path:
        return browser, ssl_key_file_path
    return browser
