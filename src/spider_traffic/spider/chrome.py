import json
import math
import os
import random
import subprocess
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import (
    WebDriverWait,  # 从selenium.webdriver.support.wait改为支持ui
)

from spider_traffic.myutils import project_path
from spider_traffic.myutils.config import SPIDER_MODE, config
from spider_traffic.myutils.logger import logger


# 生成随机数的分布符合正态分布，均值为5，方差为10，若为负数取相反数
def generate_normal_random(mean=5, variance=10):
    stddev = math.sqrt(variance)
    result = random.gauss(mean, stddev)
    if abs(result) <= 2:
        result = 2
    return abs(result)


def create_chrome_driver():
    # 在当前目录中创建download文件夹

    download_folder = os.path.join(project_path, "data", "download")
    if not os.path.exists(download_folder):
        os.makedirs(download_folder)
    # 创建 ChromeOptions 实例
    chrome_options = Options()

    if SPIDER_MODE == "xray":
        # 设置代理
        proxy_host_port = f"http://{config['proxy']['host']}:{config['proxy']['port']}"
        chrome_options.add_argument(f"--proxy-server={proxy_host_port}")
    elif SPIDER_MODE == "tor":
        # 设置代理
        proxy_host_port = (
            f"socks5://{config['proxy']['host']}:{config['proxy']['port']}"
        )
        chrome_options.add_argument(f"--proxy-server={proxy_host_port}")

    if config["spider"]["disable_quic"].lower() == "true":
        chrome_options.add_argument("--disable-quic")

    chrome_options.add_argument("--headless=new")  # 无界面模式
    chrome_options.add_argument("--disable-gpu")  # 禁用 GPU 加速
    chrome_options.add_argument("--no-sandbox")  # 禁用沙盒
    chrome_options.add_argument("--disable-dev-shm-usage")  # 限制使用/dev/shm
    chrome_options.add_argument("--incognito")  # 隐身模式
    chrome_options.add_argument("--disable-application-cache")  # 禁用应用缓存
    chrome_options.add_argument("--disable-extensions")  # 禁用扩展
    chrome_options.add_argument("--disable-infobars")  # 禁用信息栏
    chrome_options.add_argument("--disable-software-rasterizer")  # 禁用软件光栅化
    chrome_options.add_argument(
        "--autoplay-policy=no-user-gesture-required"
    )  # 允许自动播放

    # 设置实验性首选项
    prefs = {
        "profile.default_content_settings.popups": 0,
        "credentials_enable_service": False,  # 禁用密码管理器弹窗
        "profile.password_manager_enabled": False,  # 禁用密码管理器
        "download.default_directory": download_folder,  # 默认下载目录
        "download.prompt_for_download": False,  # 不提示下载
        "download.directory_upgrade": True,  # 升级下载目录
        "safebrowsing.enabled": True,  # 启用安全浏览
    }
    chrome_options.add_experimental_option("prefs", prefs)

    # 启用性能日志记录
    chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

    # 创建 WebDriver 实例
    browser = webdriver.Chrome(options=chrome_options)
    browser.execute_cdp_cmd(
        "Page.addScriptToEvaluateOnNewDocument",
        {"source": 'Object.defineProperty(navigator,"webdriver",{get:()=>undefined})'},
    )

    return browser


# 定义一个函数来滚动页面
def scroll_to_bottom(driver):
    times = 0
    last_height = driver.execute_script("return document.body.scrollHeight")
    is_continue = True
    while is_continue:
        times += 1

        delay = generate_normal_random() / times
        logger.info(f"加载等待延时: {delay}")
        time.sleep(delay)

        # 滚动到页面底部
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")

        # 使用显式等待等待页面加载新内容
        try:
            WebDriverWait(driver, 2).until(
                lambda d: d.execute_script("return document.body.scrollHeight")
                > last_height
            )
        except Exception as e:
            logger.info(f"下滑发生错误{e}")
            is_continue = False

        # 计算新的滚动高度并与最后的高度进行比较
        new_height = driver.execute_script("return document.body.scrollHeight")
        if new_height == last_height:
            is_continue = False

        if times >= int(config["spider"]["scroll_num"]):
            logger.info("达到最大下滑次数，停止下滑")
            is_continue = False

        last_height = new_height
    delay = generate_normal_random() / times
    logger.info(f"加载等待延时: {delay}")
    time.sleep(delay)


def add_cookies(browser):
    with open("youtube_cookie.txt", "r") as file:
        cookies = json.load(file)
        for cookie in cookies:
            if cookie["secure"]:
                browser.add_cookie(cookie)


def kill_chrome_processes():
    """清除浏览器进程"""
    try:
        subprocess.run(
            ["pkill", "-f", "chromedriver"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["pkill", "-f", "google-chrome"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e.stderr.decode('utf-8')}")


# # 使用示例
# browser = create_chrome_driver()
# # ... 你的其他浏览器自动化任务
# browser.quit()
