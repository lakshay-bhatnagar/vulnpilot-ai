"""MobSF CLI adapter that collects JSON output when the MobSF binary is available."""

from pathlib import Path

from backend.scanners.base import ScanExecutionResult, SubprocessScannerAdapter


class MobSFScannerAdapter(SubprocessScannerAdapter):
    name = "mobsf"
    executable_name = "mobsf"
    supported_scan_types = frozenset({"default", "android", "ios", "static"})

    def validate_target(self, target: str) -> None:
        # MobSF normally receives a local mobile application package rather than a host.
        if Path(target).expanduser().is_file():
            return
        super().validate_target(target)

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        executable = self.executable_path()
        if executable is None:
            raise RuntimeError("MobSF is not installed or not available on PATH.")
        if any(argument in {"--json", "--output", "-o"} or argument.startswith("--output=") for argument in custom_args):
            raise ValueError("MobSF output arguments are managed by VulnPilot.")
        output_path = output_dir / "mobsf.json"
        command = [executable, "scan", "--target", target, "--json", "--output", str(output_path), "--scan-type", scan_type, *custom_args]
        await self._run_command(job_id, command, output_dir)
        if not output_path.exists():
            raise RuntimeError("MobSF completed without producing JSON output.")
        return ScanExecutionResult(raw_output_path=output_path)
