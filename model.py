"""
model.py — Scoring engine and history tracker.

Provides a PhishingScorer that caches recent analyses and exposes
summary statistics.  Designed so it can later be swapped for an
ML-based model without changing the API layer.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

from detector import analyse_url

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    """One analysis record."""
    url: str
    verdict: str            # "safe" | "suspicious" | "phishing" | "error"
    confidence: float       # 0.0 - 1.0
    signals: List[dict]
    recommendation: str
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class PhishingScorer:
    """
    Thread-safe scorer that keeps a bounded history of analyses.

    Parameters
    ----------
    history_size : int
        Maximum number of past results to retain (default 500).
    """

    def __init__(self, history_size: int = 500) -> None:
        self._history: Deque[AnalysisResult] = deque(maxlen=history_size)
        self._lock = threading.Lock()

    # -- core analysis ---------------------------------------------------
    def score(self, url: str) -> AnalysisResult:
        """Run the full analysis pipeline and store the result."""
        raw = analyse_url(url)
        result = AnalysisResult(**raw)
        with self._lock:
            self._history.append(result)
        return result

    # -- batch -----------------------------------------------------------
    def score_batch(self, urls: List[str]) -> List[AnalysisResult]:
        """Score a list of URLs and return results in the same order."""
        return [self.score(u) for u in urls]

    # -- history ---------------------------------------------------------
    def history(self, n: Optional[int] = None) -> List[AnalysisResult]:
        """Return the most recent *n* results (or all if n is None)."""
        with self._lock:
            if n is None:
                return list(self._history)
            return list(self._history)[-n:]

    def clear_history(self) -> None:
        """Discard all cached results."""
        with self._lock:
            self._history.clear()

    # -- statistics ------------------------------------------------------
    def stats(self) -> Dict[str, object]:
        """Return summary statistics over the current history."""
        with self._lock:
            if not self._history:
                return {"total": 0, "verdicts": {}}

            total = len(self._history)
            verdicts: Dict[str, int] = {}
            for r in self._history:
                verdicts[r.verdict] = verdicts.get(r.verdict, 0) + 1

            avg_conf = sum(r.confidence for r in self._history) / total
            return {
                "total": total,
                "verdicts": verdicts,
                "average_confidence": round(avg_conf, 4),
            }