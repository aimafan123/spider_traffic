from spider_traffic.spider.chrome import kill_chrome_processes
from spider_traffic.spider.edge import kill_edge_processes
from spider_traffic.spider.firefox import kill_firefox_processes

# 建立配置项与函数的映射关系
BROWSER_CLEANERS = {
    "edge": kill_edge_processes,
    "chrome": kill_chrome_processes,
    "firefox": kill_firefox_processes,
}


def kill_browsers(browser_type):
    """
    根据配置列表批量关闭浏览器
    :param config_list: 例如 ["chrome", "edge"]
    """

    cleaner = BROWSER_CLEANERS.get(browser_type.lower())
    if cleaner:
        cleaner()
    else:
        print(f"Warning: No cleanup function for {browser_type}")


__all__ = ["kill_browsers"]
