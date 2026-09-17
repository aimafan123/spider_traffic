"""日志获取：优先复用项目 logger，不可用时降级为控制台输出。

``myutils/logger.py`` 在**导入期**就会打开 ``logs/defult.log``；若该文件属主为 root
（历史上用 root 跑过），普通用户导入会直接抛 ``PermissionError``。为了让连续采集至少
能以 dry-run 方式运行并给出可操作的错误提示，这里做一次显式降级。
"""

from __future__ import annotations

import logging
import sys
from typing import Tuple

FALLBACK_LOGGER_NAME = "spider_traffic.continuous"


def get_logger(level: str = "INFO") -> Tuple[logging.Logger, bool]:
    """返回 ``(logger, project_logger_ok)``。

    project_logger_ok 为 False 表示项目日志不可写、已降级为控制台输出。
    """
    numeric_level = getattr(logging, str(level).upper(), logging.INFO)
    try:
        from spider_traffic.myutils.logger import logger as project_logger

        project_logger.setLevel(numeric_level)
        return project_logger, True
    except Exception as exc:  # pragma: no cover - 取决于运行环境
        if not logging.getLogger().handlers:
            logging.basicConfig(
                level=numeric_level,
                format="%(asctime)s - %(levelname)s - %(message)s",
                stream=sys.stderr,
            )
        fallback = logging.getLogger(FALLBACK_LOGGER_NAME)
        fallback.setLevel(numeric_level)
        fallback.warning(
            "无法加载项目日志（%s）；已降级为控制台输出。"
            '修复方式： sudo chown -R "$USER" logs data',
            exc,
        )
        return fallback, False
