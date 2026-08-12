"""Asynchronous manager for real scanner runtime jobs."""

from __future__ import annotations

import asyncio
from time import monotonic

from backend.models.schemas import VulnerabilityItem
from backend.scanner_runtime.scan_storage import ScanStorage
from backend.scanner_runtime.scanner_job import RuntimeJobStatus, ScannerJob
from backend.scanner_runtime.tool_registry import ToolRegistry, build_default_registry


class ScannerManager:
    """Runs registered tools and returns normalized findings without AI enrichment."""

    def __init__(self, registry: ToolRegistry | None = None, storage: ScanStorage | None = None) -> None:
        self.registry = registry or build_default_registry()
        self.storage = storage or ScanStorage()
        self._jobs: dict[str, ScannerJob] = {}
        self._tasks: dict[str, asyncio.Task[list[VulnerabilityItem]]] = {}

    async def health_check(self) -> list[dict[str, object]]:
        return await self.registry.health()

    def get_job(self, job_id: str) -> ScannerJob | None:
        return self._jobs.get(job_id)

    async def launch(self, scanner_name: str, target: str, scan_type: str = "default", custom_args: list[str] | None = None) -> ScannerJob:
        scanner = self.registry.get(scanner_name)
        arguments = list(custom_args or [])
        scanner.validate(target, arguments)
        job = ScannerJob(scanner=scanner.name, target=target, scan_type=scan_type, custom_args=arguments)
        self._jobs[job.job_id] = job
        self.storage.write_metadata(job.job_id, {"job_id": job.job_id, "scanner": job.scanner, "target": target, "scan_type": scan_type, "status": job.status.value})
        self._tasks[job.job_id] = asyncio.create_task(self._run(job, scanner))
        return job

    async def run_and_collect(self, scanner_name: str, target: str, scan_type: str = "default", custom_args: list[str] | None = None) -> tuple[ScannerJob, list[VulnerabilityItem]]:
        job = await self.launch(scanner_name, target, scan_type, custom_args)
        return job, await self.wait(job.job_id)

    async def wait(self, job_id: str) -> list[VulnerabilityItem]:
        task = self._tasks.get(job_id)
        if task is None:
            raise ValueError(f"Runtime scanner job '{job_id}' was not found.")
        return await task

    async def cancel(self, job_id: str) -> ScannerJob:
        job = self._jobs.get(job_id)
        if job is None:
            raise ValueError(f"Runtime scanner job '{job_id}' was not found.")
        scanner = self.registry.get(job.scanner)
        await scanner.cancel(job_id)
        task = self._tasks.get(job_id)
        if task is not None and not task.done():
            task.cancel()
        return job

    async def _run(self, job: ScannerJob, scanner: object) -> list[VulnerabilityItem]:
        # Scanner type is narrowed at registration; keeping it local avoids exposing
        # scanner implementation details through API jobs.
        from backend.scanners.runtime_base import BaseScanner

        runtime_scanner = scanner
        if not isinstance(runtime_scanner, BaseScanner):
            raise RuntimeError("Registered scanner does not implement BaseScanner.")
        output_dir = self.storage.job_directory(job.job_id)
        health = await runtime_scanner.health_check()
        job.executor = "local" if health["local_available"] else "docker" if health["docker_available"] else None
        job.current_phase = f"Launching {job.scanner} container..." if job.executor == "docker" else f"Launching {job.scanner} locally..."
        job.status, job.started_at = RuntimeJobStatus.RUNNING, monotonic()
        try:
            output_path = await runtime_scanner.run(job.job_id, job.target, job.scan_type, output_dir, job.custom_args)
            findings = runtime_scanner.parse(output_path)
            job.status = RuntimeJobStatus.COMPLETED
            job.current_phase = "Parsing and normalizing scanner output"
            self.storage.write_metadata(job.job_id, {"job_id": job.job_id, "scanner": job.scanner, "target": job.target, "scan_type": job.scan_type, "status": job.status.value, "executor": job.executor, "current_phase": job.current_phase, "output_path": str(output_path), "finding_count": len(findings)})
            return findings
        except asyncio.CancelledError:
            job.status = RuntimeJobStatus.CANCELLED
            self.storage.write_metadata(job.job_id, {"job_id": job.job_id, "status": job.status.value})
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            job.status, job.error_message = RuntimeJobStatus.FAILED, str(exc)
            self.storage.write_metadata(job.job_id, {"job_id": job.job_id, "status": job.status.value, "error_message": job.error_message})
            raise
        finally:
            job.completed_at = monotonic()
