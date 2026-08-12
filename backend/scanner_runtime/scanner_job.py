"""Runtime job state independent of the API-level ScanJob model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from time import monotonic
from uuid import uuid4


class RuntimeJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScannerJob:
    scanner: str
    target: str
    scan_type: str = "default"
    custom_args: list[str] = field(default_factory=list)
    job_id: str = field(default_factory=lambda: str(uuid4()))
    status: RuntimeJobStatus = RuntimeJobStatus.QUEUED
    executor: str | None = None
    current_phase: str = "Queued"
    error_message: str | None = None
    started_at: float | None = None
    completed_at: float | None = None

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at is None:
            return None
        return (self.completed_at or monotonic()) - self.started_at
