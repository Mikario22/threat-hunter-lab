"""Threat Hunter Lab: defensively correlating synthetic identity telemetry."""
from .ingest import parse_events
from .detection import hunt

__all__ = ["parse_events", "hunt"]
