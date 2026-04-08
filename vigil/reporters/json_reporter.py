"""JSON report generator."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from vigil.models import ScanResult


class JSONReporter:
    """Generate JSON reports from scan results."""

    def generate(
        self, results: list[ScanResult], output_path: Optional[str] = None
    ) -> str:
        """Generate a JSON report and optionally write to file.

        Returns the JSON string.
        """
        report = {
            "vigil_version": "0.1.0",
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_findings": sum(r.total_count for r in results),
                "critical": sum(r.critical_count for r in results),
                "high": sum(r.high_count for r in results),
                "scanners_run": len(results),
            },
            "scanners": [r.to_dict() for r in results],
        }

        json_str = json.dumps(report, indent=2, default=str)

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json_str)

        return json_str
