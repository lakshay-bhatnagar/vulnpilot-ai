"""MobSF CLI runtime scanner."""

from pathlib import Path

from backend.parsers.mobsf_parser import parse_mobsf_json
from backend.scanners.runtime_base import BaseScanner


class MobSFScanner(BaseScanner):
    name, executable_name, docker_image, output_filename = "mobsf", "mobsf", "opensecurity/mobile-security-framework-mobsf:latest", "mobsf.json"
    supported_scan_types = frozenset({"default", "android", "ios", "static"})

    def __init__(self) -> None:
        super().__init__(parse_mobsf_json)

    def validate_target(self, target: str) -> None:
        if not Path(target).expanduser().is_file():
            raise ValueError("MobSF requires an APK or IPA package.")

    def build_local_command(self, executable: str, target: str, scan_type: str, output_path: Path, custom_args: list[str]) -> list[str]:
        return [executable, "scan", "--target", target, "--json", "--output", str(output_path), "--scan-type", scan_type, *custom_args]

    def build_docker_arguments(self, target: str, scan_type: str, custom_args: list[str]) -> list[str]:
        raise RuntimeError("MobSF is executed through its container API, not a one-shot command.")

    async def run(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str] | None = None) -> Path:
        self.validate(target, custom_args)
        if self.executable_path():
            return await super().run(job_id, target, scan_type, output_dir, custom_args)
        if not await self._docker.available():
            raise RuntimeError("MobSF is unavailable locally and Docker is not running.")
        self._executor_by_job[job_id] = self._docker
        try:
            output_path = await self._docker.execute_mobsf(job_id, self.docker_image or "", Path(target).expanduser(), output_dir, self.timeout_seconds)
            if not output_path.is_file():
                raise RuntimeError("MobSF container completed without producing JSON output.")
            return output_path
        finally:
            self._executor_by_job.pop(job_id, None)
