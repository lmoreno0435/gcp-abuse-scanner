"""HTML reporter — self-contained report using Jinja2."""

from __future__ import annotations

from pathlib import Path

import jinja2

from gcp_abuse_scanner.models.finding import Severity
from gcp_abuse_scanner.models.report import ScanReport

_SEVERITY_COLOR: dict[str, str] = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}

_VECTOR_LABEL: dict[str, str] = {
    "crypto_mining": "⛏ Crypto Mining",
    "gemini_abuse": "🤖 Gemini Abuse",
    "common": "🔧 Common",
}


def _severity_color(severity: str | Severity) -> str:
    """Return the hex color for a given severity level."""
    key = Severity(severity) if isinstance(severity, str) else severity
    return _SEVERITY_COLOR.get(key, "#6b7280")


def _severity_badge(severity: str | Severity) -> str:
    """Return an inline HTML badge for the given severity."""
    color = _severity_color(severity)
    label = severity.value if isinstance(severity, Severity) else str(severity)
    return (
        f'<span style="'
        f"display:inline-block;"
        f"border-radius:4px;"
        f"padding:2px 8px;"
        f"font-size:12px;"
        f"font-weight:600;"
        f"color:{color};"
        f"background:rgba(0,0,0,0.06);"
        f'border:1px solid {color}40">'
        f"{label}</span>"
    )


def _vector_label(vector: str) -> str:
    """Return a human-readable label for a vector slug."""
    return _VECTOR_LABEL.get(str(vector), str(vector))


class HTMLReporter:
    """Renders a ScanReport as a self-contained HTML file using Jinja2."""

    def __init__(self, output_path: str | Path | None = None) -> None:
        self._output_path = Path(output_path) if output_path else None

        templates_dir = Path(__file__).parent / "templates"
        loader = jinja2.FileSystemLoader(str(templates_dir))
        self._env = jinja2.Environment(
            loader=loader,
            autoescape=jinja2.select_autoescape(["html", "j2"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # Register custom filters
        self._env.filters["severity_color"] = _severity_color
        self._env.filters["severity_badge"] = _severity_badge
        self._env.filters["vector_label"] = _vector_label

    def render(self, report: ScanReport) -> str:
        """Render the HTML report and optionally write it to disk.

        Args:
            report: The completed ScanReport to render.

        Returns:
            The rendered HTML string.
        """
        template = self._env.get_template("report.html.j2")
        html = template.render(report=report)

        if self._output_path:
            self._output_path.parent.mkdir(parents=True, exist_ok=True)
            self._output_path.write_text(html, encoding="utf-8")

        return html
