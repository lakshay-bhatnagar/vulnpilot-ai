from pathlib import Path

from backend.scanners.base import ScanExecutionResult, SubprocessScannerAdapter


class NessusScannerAdapter(SubprocessScannerAdapter):
    name = "nessus"
    executable_name = "nessus"
    supported_scan_types = frozenset({"default", "host", "web", "compliance"})

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        raise RuntimeError("Nessus execution is not configured. Import Nessus exports through the upload workflow.")
