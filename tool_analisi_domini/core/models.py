from dataclasses import dataclass, asdict
from typing import Any, Dict, List


@dataclass
class SectionResult:
    name: str
    score: float
    max_score: float
    status: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["score_percent"] = round(100 * self.score / self.max_score, 2) if self.max_score else 0.0
        return d


@dataclass
class ScanReport:
    target: str
    timestamp_utc: str
    sections: List[SectionResult]

    @property
    def total_score(self) -> float:
        return sum(s.score for s in self.sections)

    @property
    def max_total_score(self) -> float:
        return sum(s.max_score for s in self.sections)

    @property
    def total_score_percent(self) -> float:
        if not self.max_total_score:
            return 0.0
        return round(100 * self.total_score / self.max_total_score, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "timestamp_utc": self.timestamp_utc,
            "total_score": self.total_score,
            "max_total_score": self.max_total_score,
            "total_score_percent": self.total_score_percent,
            "sections": [s.to_dict() for s in self.sections],
        }
