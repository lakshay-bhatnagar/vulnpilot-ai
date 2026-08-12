"""Local, no-shell asynchronous process executor."""

from __future__ import annotations

import asyncio
from pathlib import Path


class LocalExecutor:
    name = "local"

    def __init__(self) -> None:
        self._processes: dict[str, asyncio.subprocess.Process] = {}

    @staticmethod
    def available() -> bool:
        return True

    async def execute(self, job_id: str, command: list[str], output_dir: Path, timeout_seconds: int) -> None:
        if not command or any(not item or "\x00" in item for item in command):
            raise ValueError("Scanner command contains an invalid argument.")
        stderr_path = output_dir / "stderr.log"
        try:
            process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        except FileNotFoundError as exc:
            raise RuntimeError(f"Scanner executable '{command[0]}' was not found on PATH.") from exc
        except PermissionError as exc:
            raise RuntimeError(f"Permission denied while starting scanner '{command[0]}'.") from exc
        self._processes[job_id] = process
        try:
            _, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise RuntimeError(f"Scanner timed out after {timeout_seconds} seconds.") from exc
        except asyncio.CancelledError:
            await self.cancel(job_id)
            raise
        finally:
            self._processes.pop(job_id, None)
        stderr_path.write_bytes(stderr or b"")
        if process.returncode != 0:
            message = (stderr or b"").decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Scanner exited with code {process.returncode}: {message[:500]}")

    async def cancel(self, job_id: str) -> None:
        process = self._processes.get(job_id)
        if process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except TimeoutError:
                process.kill()
                await process.wait()
