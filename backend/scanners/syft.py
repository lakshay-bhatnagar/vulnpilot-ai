"""Runtime Syft SBOM generator; SBOMs are real artifacts but do not imply vulnerabilities."""

import shutil
from pathlib import Path

from backend.scanners.runtime_base import BaseScanner


class SyftScanner(BaseScanner):
    name, executable_name, docker_image, output_filename = "syft", "syft", "anchore/syft:latest", "sbom.cdx.json"

    def validate_target(self, target: str) -> None:
        if not Path(target).expanduser().is_dir():
            raise ValueError("Syft requires a project directory.")

    def build_local_command(self, executable: str, target: str, scan_type: str, output_path: Path, custom_args: list[str]) -> list[str]:
        return [executable, f"dir:{target}", "-o", f"cyclonedx-json={output_path}", *custom_args]

    def build_docker_arguments(self, target: str, scan_type: str, custom_args: list[str]) -> list[str]:
        return [f"dir:{target}", "-o", f"cyclonedx-json=/workspace/output/{self.output_filename}", *custom_args]

    async def run(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str] | None = None) -> Path:
        output = await super().run(job_id, target, scan_type, output_dir, custom_args)
        shutil.copyfile(output, Path(target).expanduser() / self.output_filename)
        return output
