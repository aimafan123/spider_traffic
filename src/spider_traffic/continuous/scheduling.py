"""monitored / background 站点调度器。

调度策略（对应需求）：

- **monitored 均衡**：每次从「已访问次数最少」的站点中随机挑一个，因此任意时刻
  各 monitored 站点的访问次数最多相差 1，长期完全均衡；
- **background 不放回**：默认 ``shuffled_cycle`` —— 先把列表洗牌，按顺序取完一轮
  再洗下一轮，即「随机打乱后不放回采样」。洗牌结果由 ``(seed, cycle_index)`` 决定，
  因此状态文件只需保存轮次与偏移，不必保存整个列表；
- **monitored 比例**：``bernoulli`` 每次访问独立按 p 抽样（间隔服从几何分布，天然随机）；
  ``exact`` 用累加器保证长期比例精确等于 p。
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

MONITORED = "monitored"
BACKGROUND = "background"
CATEGORIES = (MONITORED, BACKGROUND)


@dataclass
class SiteChoice:
    """一次调度决策的结果。"""

    site: str
    category: str


class SiteScheduler:
    """按 monitored 比例在两类站点间随机混合。"""

    def __init__(
        self,
        monitored: List[str],
        background: List[str],
        ratio: float,
        seed: int,
        ratio_mode: str = "bernoulli",
        background_sampling: str = "shuffled_cycle",
        state: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.monitored = list(monitored)
        self.background = list(background)
        self.ratio = float(ratio)
        self.seed = int(seed)
        self.ratio_mode = ratio_mode
        self.background_sampling = background_sampling
        self._rng = random.Random(self.seed)

        state = state or {}
        self.visits_total = int(state.get("visits_total", 0))
        self.monitored_visits = int(state.get("monitored_visits", 0))
        self.background_visits = int(state.get("background_visits", 0))
        self._credit = float(state.get("credit", 0.0))
        saved_counts = state.get("monitored_counts") or {}
        self.monitored_counts: Dict[str, int] = {
            site: int(saved_counts.get(site, 0)) for site in self.monitored
        }
        self._background_cycle_index = int(state.get("background_cycle_index", 0))
        self._background_cycle_pos = int(state.get("background_cycle_pos", 0))
        self._background_cycle: Optional[List[str]] = None
        self._last_background: Optional[str] = state.get("last_background")

    # ------------------------------------------------------------------ #
    # 对外接口
    # ------------------------------------------------------------------ #
    def next_choice(self) -> SiteChoice:
        """返回下一次要访问的站点及其类别。"""
        category = self._next_category()
        if category == MONITORED:
            site = self._pick_monitored()
            self.monitored_visits += 1
        else:
            site = self._pick_background()
            self.background_visits += 1
        self.visits_total += 1
        return SiteChoice(site=site, category=category)

    def snapshot(self) -> Dict[str, Any]:
        """可 JSON 化的状态，用于跨重启续跑（均衡性与背景轮次都不丢失）。"""
        return {
            "visits_total": self.visits_total,
            "monitored_visits": self.monitored_visits,
            "background_visits": self.background_visits,
            "credit": self._credit,
            "monitored_counts": dict(self.monitored_counts),
            "background_cycle_index": self._background_cycle_index,
            "background_cycle_pos": self._background_cycle_pos,
            "last_background": self._last_background,
        }

    def stats(self) -> Dict[str, Any]:
        """运行统计：比例、均衡性、背景轮次。"""
        counts = list(self.monitored_counts.values())
        spread = (max(counts) - min(counts)) if counts else 0
        observed = (self.monitored_visits / self.visits_total) if self.visits_total else 0.0
        return {
            "visits_total": self.visits_total,
            "monitored_visits": self.monitored_visits,
            "background_visits": self.background_visits,
            "target_ratio": self.ratio,
            "observed_ratio": observed,
            "monitored_count_min": min(counts) if counts else 0,
            "monitored_count_max": max(counts) if counts else 0,
            "monitored_spread": spread,
            "background_cycle_index": self._background_cycle_index,
            "background_cycle_pos": self._background_cycle_pos,
        }

    # ------------------------------------------------------------------ #
    # 内部实现
    # ------------------------------------------------------------------ #
    def _next_category(self) -> str:
        # 只有一类站点时直接退化，避免比例配置导致空转
        if not self.background:
            return MONITORED
        if not self.monitored:
            return BACKGROUND

        if self.ratio_mode == "exact":
            self._credit += self.ratio
            if self._credit >= 1.0 - 1e-9:
                self._credit -= 1.0
                return MONITORED
            return BACKGROUND

        return MONITORED if self._rng.random() < self.ratio else BACKGROUND

    def _pick_monitored(self) -> str:
        """在访问次数最少的站点中随机挑选，保证长期完全均衡。"""
        if not self.monitored:
            raise RuntimeError("monitored 列表为空，无法调度")
        minimum = min(self.monitored_counts.values())
        candidates = [
            site for site in self.monitored if self.monitored_counts[site] == minimum
        ]
        site = self._rng.choice(candidates)
        self.monitored_counts[site] += 1
        return site

    def _pick_background(self) -> str:
        if not self.background:
            raise RuntimeError("background 列表为空，无法调度")
        if self.background_sampling == "random_choice":
            return self._rng.choice(self.background)

        cycle = self._current_background_cycle()
        site = cycle[self._background_cycle_pos]
        self._background_cycle_pos += 1
        self._last_background = site
        if self._background_cycle_pos >= len(cycle):
            self._background_cycle_index += 1
            self._background_cycle_pos = 0
            self._background_cycle = None
        return site

    def _current_background_cycle(self) -> List[str]:
        if self._background_cycle is None:
            self._background_cycle = self._build_background_cycle(
                self._background_cycle_index
            )
        return self._background_cycle

    def _build_background_cycle(self, index: int) -> List[str]:
        """用 ``(seed, category, index)`` 确定性洗牌，保证可复现与可续跑。"""
        items = list(self.background)
        rng = random.Random(f"{self.seed}|{BACKGROUND}|{index}")
        rng.shuffle(items)
        # 轮次交界处避免与上一轮最后一个站点相邻重复
        if len(items) > 1 and items[0] == self._last_background:
            swap_with = rng.randrange(1, len(items))
            items[0], items[swap_with] = items[swap_with], items[0]
        return items
