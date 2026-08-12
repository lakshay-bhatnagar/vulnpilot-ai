"""Common real-execution scanner contract used by scanner_runtime."""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from backend.models.schemas import VulnerabilityItem
from backend.scanner_runtime.docker_executor import DockerExecutor
from backend.scanner_runtime.local_executor import LocalExecutor

FindingParser = Callable[[bytes], list[VulnerabilityItem]]


class BaseScanner(ABC):
    """A scanner with real local/Docker execution and normalized output."""

    name: str
    executable_name: str
    docker_image: str | None = None
    timeout_seconds = 3600
    supported_scan_types = frozenset({"default"})
    output_filename: str

    def __init__(self, parser: FindingParser | None = None) -> None:
        self._parser = parser or (lambda _: [])
        self._local = LocalExecutor()
        self._docker = DockerExecutor()
        self._executor_by_job: dict[str, LocalExecutor | DockerExecutor] = {}

    def executable_path(self) -> str | None:
        return shutil.which(self.executable_name)

    def validate(self, target: str, custom_args: list[str] | None = None) -> None:
        candidate = target.strip()
        if not candidate or "\x00" in candidate or candidate.startswith("-"):
            raise ValueError("Target must be non-empty and cannot begin with '-'.")
        if any(not argument or "\x00" in argument for argument in custom_args or []):
            raise ValueError("Scanner arguments must be non-empty and cannot contain null bytes.")
        self.validate_target(candidate)

    def validate_target(self, target: str) -> None:
        if any(character.isspace() for character in target):
            raise ValueError("Network targets cannot contain whitespace.")
        parsed = urlparse(target if "://" in target else f"//{target}")
        if not parsed.hostname:
            raise ValueError("Target must contain a valid hostname or IP address.")

    def supports_scan_type(self, scan_type: str) -> bool:
        return scan_type.lower() in self.supported_scan_types

    async def health_check(self) -> dict[str, object]:
        local_path = self.executable_path()
        docker_available = await self._docker.available() if self.docker_image else False
        return {"scanner": self.name, "local_available": bool(local_path), "local_path": local_path, "docker_available": docker_available, "docker_image": self.docker_image, "available": bool(local_path) or docker_available}

    async def _select_executor(self) -> LocalExecutor | DockerExecutor:
        if self.executable_path():
            return self._local
        if self.docker_image and await self._docker.available():
            return self._docker
        source = "or Docker" if self.docker_image else ""
        raise RuntimeError(f"{self.name} is not installed locally {source} is not available.")

    @abstractmethod
    def build_local_command(self, executable: str, target: str, scan_type: str, output_path: Path, custom_args: list[str]) -> list[str]:
        """Build a tool-native argv; output paths must remain runtime managed."""

    @abstractmethod
    def build_docker_arguments(self, target: str, scan_type: str, custom_args: list[str]) -> list[str]:
        """Build argv for the image entrypoint, using /output for artifacts."""

    def _docker_command(self, arguments: list[str]) -> list[str]:
        docker = DockerExecutor.executable()
        if docker is None or not self.docker_image:
            raise RuntimeError(f"Docker runtime is unavailable for {self.name}.")
        # DockerExecutor replaces this marker with a unique TemporaryDirectory.
        # No user-provided source path is ever mounted into a scanner container.
        command = [docker, "run", "--rm", "--network", "bridge", "--cap-drop", "ALL", "--cap-add", "NET_RAW", "-v", f"{DockerExecutor.WORKSPACE_MARKER}:/workspace"]
        return [*command, self.docker_image, *arguments]

    def after_execute(self, output_dir: Path, output_path: Path) -> None:
        """Validate or materialize the native artifact after a successful real process."""

    async def run(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str] | None = None) -> Path:
        arguments = list(custom_args or [])
        self.validate(target, arguments)
        if not self.supports_scan_type(scan_type):
            raise ValueError(f"{self.name} does not support scan type '{scan_type}'.")
        output_dir.mkdir(parents=True, exist_ok=True)
        executor = await self._select_executor()
        self._executor_by_job[job_id] = executor
        output_path = output_dir / self.output_filename
        try:
            if executor.name == "local":
                executable = self.executable_path()
                if executable is None:
                    raise RuntimeError(f"{self.name} local executable disappeared from PATH.")
                command = self.build_local_command(executable, target, scan_type, output_path, arguments)
            else:
                target_path = Path(target).expanduser()
                docker_target = "/workspace/input/project" if target_path.is_dir() else f"/workspace/input/{target_path.name}" if target_path.is_file() else target
                command = self._docker_command(self.build_docker_arguments(docker_target, scan_type, arguments))
            if executor.name == "docker":
                await executor.execute(job_id, command, output_dir, self.timeout_seconds, target_path if target_path.exists() else None)
            else:
                await executor.execute(job_id, command, output_dir, self.timeout_seconds)
            self.after_execute(output_dir, output_path)
            if not output_path.is_file():
                raise RuntimeError(f"{self.name} completed without producing {self.output_filename}.")
            return output_path
        finally:
            self._executor_by_job.pop(job_id, None)

    def parse(self, output_path: Path) -> list[VulnerabilityItem]:
        return self.normalize(self._parser(output_path.read_bytes()))

    def normalize(self, findings: list[VulnerabilityItem]) -> list[VulnerabilityItem]:
        return findings

    async def cancel(self, job_id: str) -> None:
        executor = self._executor_by_job.get(job_id)
        if executor is not None:
            await executor.cancel(job_id)
