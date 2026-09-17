"""Continuous Collection：不依赖 Scrapy 的连续流量采集子系统。

本包与现有单 trace 流程（``main.py`` / ``action.py``）完全独立：
- 不导入、不修改 ``spider/middlewares.py``、``spider/spiders/trace.py``；
- 只复用 ``spider/`` 下的浏览器创建逻辑与 ``myutils`` 的路径/日志工具；
- 通过 YAML 配置驱动，入口为 ``python -m spider_traffic.continuous``。

详见同目录 ``README.md``。
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
