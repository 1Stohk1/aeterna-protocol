from __future__ import annotations

from dataclasses import dataclass, field

from core.poc import REJECTED, VALIDATED


@dataclass(slots=True)
class TrustScoreBook:
    """Minimal v0.1 PoC trust bookkeeping.

    This is only the Level-2 rolling delta. The weighted multi-level Trust
    Score from CONSENSUS.md remains a chain/governance concern.
    """

    _scores: dict[str, int] = field(default_factory=dict)

    def apply_poc_verdict(self, guardian_id: str, verdict: str) -> int:
        delta = self.delta_for_verdict(verdict)
        self._scores[guardian_id] = self._scores.get(guardian_id, 0) + delta
        return delta

    def get(self, guardian_id: str) -> int:
        return self._scores.get(guardian_id, 0)

    @staticmethod
    def delta_for_verdict(verdict: str) -> int:
        if verdict == VALIDATED:
            return 1
        if verdict == REJECTED:
            return -1
        return 0
