"""Common contracts and safe subprocess helpers for scanner adapters."""

from __future__ import annotations

import asyncio
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from backend.models.schemas import VulnerabilityItem


@dataclass(frozen=True)
class ScanExecutionResult:
    raw_output_path: Path
    finding_count: int = 0


class ScannerAdapter(ABC):
    """Executable scanner integration behind a stable orchestration interface."""

    name: str
    executable_name: str
    supported_scan_types: frozenset[str] = frozenset({"default"})

    def executable_path(self) -> str | None:
        return shutil.which(self.executable_name)

    def validate_target(self, target: str) -> None:
        candidate = target.strip()
        if not candidate or candidate.startswith("-") or any(character.isspace() for character in candidate):
            raise ValueError("Target must be a non-empty host, IP address, CIDR, or URL without whitespace.")
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        if not parsed.hostname:
            raise ValueError("Target must contain a valid hostname or IP address.")

    def validate(self, target: str) -> None:
        """Profile-friendly alias for target validation."""
        self.validate_target(target)

    @abstractmethod
    async def run_scan(
        self,
        job_id: str,
        target: str,
        scan_type: str,
        output_dir: Path,
        custom_args: list[str],
    ) -> ScanExecutionResult:
        """Run a scanner and write native output inside output_dir."""

    async def run(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        """Profile-friendly alias for safe scanner execution."""
        return await self.run_scan(job_id, target, scan_type, output_dir, custom_args)

    @abstractmethod
    async def cancel_scan(self, job_id: str) -> None:
        """Stop an in-flight scanner process."""

    @abstractmethod
    def parse_results(self, raw_results: Any) -> list[Any]:
        """Parse scanner-native output into intermediate records (not invoked yet)."""

    @abstractmethod
    def normalize(self, parsed_results: list[Any]) -> list[VulnerabilityItem]:
        """Normalize results into findings (not invoked by orchestration execution)."""

    def parse(self, raw_results: Any) -> list[VulnerabilityItem]:
        """Parse and normalize output through the adapter's shared parser path."""
        return self.normalize(self.parse_results(raw_results))

    def supports_scan_type(self, scan_type: str) -> bool:
        return scan_type.lower() in self.supported_scan_types


class SubprocessScannerAdapter(ScannerAdapter):
    """Shared no-shell subprocess handling with timeout and cancellation support."""

    timeout_seconds = 3600

    def __init__(self) -> None:
        self._processes: dict[str, asyncio.subprocess.Process] = {}

    async def _run_command(self, job_id: str, command: list[str], output_dir: Path, stdout_path: Path | None = None) -> None:
        stderr_path = output_dir / "stderr.log"
        stdout_file = stdout_path.open("wb") if stdout_path is not None else None
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=stdout_file or asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            if stdout_file is not None:
                stdout_file.close()
            raise RuntimeError(f"Scanner executable '{self.executable_name}' was not found on PATH.") from exc
        except PermissionError as exc:
            if stdout_file is not None:
                stdout_file.close()
            raise RuntimeError(f"Permission denied while starting scanner '{self.executable_name}'.") from exc

        self._processes[job_id] = process
        try:
            _, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout_seconds)
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise RuntimeError(f"{self.name} scan timed out after {self.timeout_seconds} seconds.") from exc
        except asyncio.CancelledError:
            if process.returncode is None:
                process.terminate()
                await process.wait()
            raise
        finally:
            self._processes.pop(job_id, None)
            if stdout_file is not None:
                stdout_file.close()

        stderr_path.write_bytes(stderr or b"")
        if process.returncode != 0:
            message = (stderr or b"").decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"{self.name} exited with code {process.returncode}: {message[:500]}")

    async def cancel_scan(self, job_id: str) -> None:
        process = self._processes.get(job_id)
        if process is not None and process.returncode is None:
            process.terminate()

    def parse_results(self, raw_results: Any) -> list[Any]:
        return []

    def normalize(self, parsed_results: list[Any]) -> list[VulnerabilityItem]:
        return []
