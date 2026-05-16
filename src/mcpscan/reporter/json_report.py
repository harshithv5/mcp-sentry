"""Render a ScanReport as JSON."""
from ..models import ScanReport


def render_json(report: ScanReport, indent: int = 2) -> str:
    return report.model_dump_json(indent=indent)
