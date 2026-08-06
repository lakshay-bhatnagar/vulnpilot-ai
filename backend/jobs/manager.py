"""In-memory job store and per-job update streams for scan orchestration."""

import asyncio
from datetime import UTC, datetime
from threading import RLock

from backend.jobs.models import CreateScanJobRequest, ScanJob, ScanJobStatus


class ScanJobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        # Each connected SSE client receives an independent queue.  This means
        # clients monitoring separate jobs (or the same job) never consume one
        # another's status updates.
        self._subscribers: dict[str, set[asyncio.Queue[ScanJob]]] = {}
        self._lock = RLock()

    def create(self, request: CreateScanJobRequest) -> ScanJob:
        job = ScanJob(scanner=request.scanner, target=request.target, scan_type=request.scan_type)
        with self._lock:
            self._jobs[job.job_id] = job
            self._publish(job)
        return job

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[ScanJob]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda job: job.created_time, reverse=True)

    def cancel(self, job_id: str) -> ScanJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            if job.status in {ScanJobStatus.COMPLETED, ScanJobStatus.FAILED, ScanJobStatus.CANCELLED}:
                raise ValueError(f"Job '{job_id}' is already in terminal state {job.status.value}.")
            cancelled = job.model_copy(
                update={
                    "status": ScanJobStatus.CANCELLED,
                    "current_phase": "Cancelled before execution",
                    "completed_time": datetime.now(UTC),
                    "duration": (datetime.now(UTC) - job.created_time).total_seconds(),
                }
            )
            self._jobs[job_id] = cancelled
            self._publish(cancelled)
            return cancelled

    def update(self, job_id: str, **updates: object) -> ScanJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            updated = job.model_copy(update=updates)
            self._jobs[job_id] = updated
            self._publish(updated)
            return updated

    def subscribe(self, job_id: str) -> tuple[ScanJob, asyncio.Queue[ScanJob]] | None:
        """Register one SSE client and atomically return its initial snapshot."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            queue: asyncio.Queue[ScanJob] = asyncio.Queue(maxsize=32)
            self._subscribers.setdefault(job_id, set()).add(queue)
            return job, queue

    def unsubscribe(self, job_id: str, queue: asyncio.Queue[ScanJob]) -> None:
        with self._lock:
            subscribers = self._subscribers.get(job_id)
            if subscribers is None:
                return
            subscribers.discard(queue)
            if not subscribers:
                self._subscribers.pop(job_id, None)

    def _publish(self, job: ScanJob) -> None:
        """Publish the latest snapshot without allowing a slow client to block jobs."""
        for queue in tuple(self._subscribers.get(job.job_id, ())):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(job)
            except asyncio.QueueFull:
                # The next update will replace the stale state; execution must
                # never be delayed by an inactive browser tab.
                continue
