from __future__ import annotations

import json
from pathlib import Path

from core.models import ScanResult


class JSONReporter:
    """Formats and exports ScanResult as a JSON document."""

    def render(self, result: ScanResult) -> str:
        return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)

    def export(self, result: ScanResult, output_path: str | Path) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(result), encoding="utf-8")
        return path
