import json
from pathlib import Path
from typing import Any, Dict

from ..core.models import ScanReport


def export_json(report: ScanReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)
