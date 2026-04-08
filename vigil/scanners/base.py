"""Base scanner interface."""

from __future__ import annotations

import abc
from datetime import datetime

from vigil.models import ScanResult


class BaseScanner(abc.ABC):
    """Abstract base class for all scanners."""

    name: str = "base"

    @abc.abstractmethod
    async def scan(self) -> ScanResult:
        """Execute the scan and return results."""

    def _make_result(self) -> ScanResult:
        return ScanResult(scanner_name=self.name, started_at=datetime.utcnow())

    def _finish_result(self, result: ScanResult) -> ScanResult:
        result.finished_at = datetime.utcnow()
        return result
