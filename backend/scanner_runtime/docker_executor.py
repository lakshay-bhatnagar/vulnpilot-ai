"""Docker CLI executor using argument arrays and no shell."""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from uuid import uuid4
from pathlib import Path

import httpx

from backend.scanner_runtime.local_executor import LocalExecutor


class DockerExecutor:
    name = "docker"
    WORKSPACE_MARKER = "__VULNPILOT_WORKSPACE__"

    def __init__(self) -> None:
        self._local = LocalExecutor()
        self._containers: dict[str, str] = {}

    @staticmethod
    def executable() -> str | None:
        return shutil.which("docker")

    async def available(self) -> bool:
        executable = self.executable()
        if executable is None:
            return False
        try:
            process = await asyncio.create_subprocess_exec(executable, "info", "--format", "{{.ServerVersion}}", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            return await asyncio.wait_for(process.wait(), timeout=5) == 0
        except (OSError, TimeoutError):
            return False

    @staticmethod
    def _stage_target(workspace: Path, target: Path | None) -> None:
        if target is None:
            return
        input_root = workspace / "input"
        input_root.mkdir()
        if target.is_dir():
            shutil.copytree(target, input_root / "project", symlinks=False, ignore_dangling_symlinks=True)
        elif target.is_file():
            shutil.copy2(target, input_root / target.name)

    @staticmethod
    def _copy_outputs(workspace: Path, output_dir: Path) -> None:
        staged_output = workspace / "output"
        if not staged_output.is_dir():
            return
        for item in staged_output.iterdir():
            destination = output_dir / item.name
            if item.is_dir():
                if destination.exists():
                    shutil.rmtree(destination)
                shutil.copytree(item, destination)
            else:
                shutil.copy2(item, destination)

    async def execute(self, job_id: str, command: list[str], output_dir: Path, timeout_seconds: int, source_target: Path | None = None) -> None:
        """Run a complete Docker argv with only a disposable workspace mounted.

        The command must use ``WORKSPACE_MARKER`` in its volume argument. Source
        material is copied into the workspace first; output is copied back only
        after Docker exits successfully, then the workspace is removed.
        """
        if not any(self.WORKSPACE_MARKER in argument for argument in command):
            raise ValueError("Docker command must mount the isolated scanner workspace.")
        with tempfile.TemporaryDirectory(prefix=f"vulnpilot-{job_id}-") as temporary_directory:
            workspace = Path(temporary_directory)
            (workspace / "output").mkdir()
            self._stage_target(workspace, source_target)
            resolved_command = [argument.replace(self.WORKSPACE_MARKER, str(workspace)) for argument in command]
            await self._local.execute(job_id, resolved_command, output_dir, timeout_seconds)
            self._copy_outputs(workspace, output_dir)

    async def execute_mobsf(self, job_id: str, image: str, package: Path, output_dir: Path, timeout_seconds: int) -> Path:
        """Run a real ephemeral MobSF API container and persist its JSON report."""
        api_key = os.environ.get("MOBSF_API_KEY")
        docker = self.executable()
        if not api_key:
            raise RuntimeError("MOBSF_API_KEY is required to collect a MobSF container report.")
        if docker is None:
            raise RuntimeError("Docker is unavailable for MobSF execution.")
        with tempfile.TemporaryDirectory(prefix=f"vulnpilot-{job_id}-") as temporary_directory:
            workspace = Path(temporary_directory)
            self._stage_target(workspace, package)
            container_name = f"vulnpilot-mobsf-{uuid4().hex[:16]}"
            start = [docker, "run", "-d", "--rm", "--name", container_name, "-p", "127.0.0.1::8000", "-v", f"{workspace}:/workspace:ro", image]
            await self._local.execute(job_id, start, output_dir, timeout_seconds=30)
            self._containers[job_id] = container_name
            try:
                port_process = await asyncio.create_subprocess_exec(docker, "port", container_name, "8000/tcp", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                port_bytes, _ = await asyncio.wait_for(port_process.communicate(), timeout=10)
                if port_process.returncode != 0 or not port_bytes:
                    raise RuntimeError("MobSF container did not expose its API port.")
                endpoint = f"http://{port_bytes.decode().strip().rsplit(':', 1)[0]}:{port_bytes.decode().strip().rsplit(':', 1)[1]}"
                headers = {"Authorization": api_key}
                async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_seconds)) as client:
                    for _ in range(30):
                        try:
                            if (await client.get(f"{endpoint}/api_docs")).status_code < 500:
                                break
                        except httpx.HTTPError:
                            await asyncio.sleep(1)
                    else:
                        raise RuntimeError("MobSF container did not become ready in time.")
                    staged_package = workspace / "input" / package.name
                    with staged_package.open("rb") as handle:
                        upload = await client.post(f"{endpoint}/api/v1/upload", headers=headers, files={"file": (package.name, handle, "application/octet-stream")})
                    upload.raise_for_status()
                    scan_hash = upload.json().get("hash")
                    if not scan_hash:
                        raise RuntimeError("MobSF did not return an uploaded package hash.")
                    scan = await client.post(f"{endpoint}/api/v1/scan", headers=headers, data={"hash": scan_hash})
                    scan.raise_for_status()
                    report = await client.post(f"{endpoint}/api/v1/report_json", headers=headers, data={"hash": scan_hash})
                    report.raise_for_status()
                    output_path = workspace / "output" / "mobsf.json"
                    output_path.write_bytes(report.content)
                self._copy_outputs(workspace, output_dir)
                return output_dir / "mobsf.json"
            finally:
                await self.cancel(job_id)

    async def cancel(self, job_id: str) -> None:
        await self._local.cancel(job_id)
        container = self._containers.pop(job_id, None)
        docker = self.executable()
        if container and docker:
            process = await asyncio.create_subprocess_exec(docker, "rm", "-f", container, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await process.wait()
