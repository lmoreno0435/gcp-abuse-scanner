"""JSON reporter — canonical output format."""

from __future__ import annotations

import json
from pathlib import Path

from gcp_abuse_scanner.models.report import ScanReport


class JSONReporter:
    def __init__(self, output_path: str | Path | None = None, indent: int = 2) -> None:
        self._output_path = Path(output_path) if output_path else None
        self._indent = indent

    def render(self, report: ScanReport) -> str:
        data = report.model_dump(mode="json")
        output = json.dumps(data, indent=self._indent, default=str)
        if self._output_path:
            self._output_path.write_text(output, encoding="utf-8")
        return output
