"""Ground truth 记录：每次网站访问写一行 JSON（JSONL）。

每行字段见 :class:`VisitRecord`。写入后立即 ``flush``，因此即使进程被强杀，
已经完成的访问记录也不会丢失。
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterator, Optional


@dataclass
class VisitRecord:
    """一次网站访问的 ground truth。"""

    visit_index: int
    vps: str
    site: str
    url: str
    category: str                       # monitored | background
    start_time: str                     # ISO8601（含时区）
    end_time: str                       # ISO8601（含时区）
    duration_seconds: float
    success: bool
    error: Optional[str] = None
    error_type: Optional[str] = None
    landed_url: Optional[str] = None
    page_title: Optional[str] = None
    browser: str = ""
    browser_session_id: Optional[int] = None   # 第几个浏览器会话（每 N 次访问重启一次）
    visit_in_session: Optional[int] = None     # 该会话内的第几次访问
    pcap_file: Optional[str] = None      # 访问开始时正在写入的 pcap
    pcap_file_at_end: Optional[str] = None  # 访问结束时正在写入的 pcap（跨桶时不同）
    keylog_file: Optional[str] = None    # 该时间桶的 TLS keylog
    monitored_ratio_target: float = 0.0
    monitored_ratio_observed: float = 0.0
    dry_run: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class GroundTruthWriter:
    """JSONL 追加写入器。"""

    def __init__(self, path: str, logger) -> None:
        self.path = path
        self.logger = logger
        self.count = 0
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._handle = open(path, "a", encoding="utf-8")

    def write(self, record: VisitRecord) -> None:
        line = json.dumps(record.to_dict(), ensure_ascii=False)
        self._handle.write(line + "\n")
        self._handle.flush()
        self.count += 1

    def close(self) -> None:
        if self._handle and not self._handle.closed:
            try:
                self._handle.flush()
                os.fsync(self._handle.fileno())
            except OSError:
                pass
            self._handle.close()

    def __enter__(self) -> "GroundTruthWriter":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self.close()
        return False


def iter_records(path: str) -> Iterator[Dict[str, Any]]:
    """读取 JSONL ground truth，供分析脚本复用。"""
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)
