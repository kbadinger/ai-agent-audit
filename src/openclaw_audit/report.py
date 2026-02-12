"""HTML report generation from audit findings."""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .config import AUDIT_REPORTS
from .db import FindingsDB


def _timestamp_fmt(ts: float) -> str:
    """Format a unix timestamp for display."""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


class ReportGenerator:
    """Generates standalone HTML audit reports."""

    def __init__(self, db: FindingsDB | None = None):
        self.db = db or FindingsDB()
        templates_dir = Path(__file__).parent / "templates"
        self._env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=True,
        )
        self._env.filters["timestamp_fmt"] = _timestamp_fmt

    def generate(self) -> Path:
        """Generate an HTML report and return the file path."""
        findings = self.db.get_active_findings()
        trend_data = self.db.get_trend_data(days=30)

        # Extract security score and grade from the finding title.
        # Title format: "Security Score: 95/140 (Grade: B)"
        score = None
        grade = None
        for f in findings:
            if f.get("module") == "security_score":
                import re
                m = re.search(r"(\d+)/\d+\s*\(Grade:\s*([A-F])\)", f["title"])
                if m:
                    score = int(m.group(1))
                    grade = m.group(2)
                break

        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        template = self._env.get_template("report.html.j2")
        html = template.render(
            findings=findings,
            trend_data=trend_data,
            generated_at=generated_at,
            score=score,
            grade=grade,
        )

        AUDIT_REPORTS.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = AUDIT_REPORTS / f"report-{timestamp}.html"
        out_path.write_text(html)

        return out_path
