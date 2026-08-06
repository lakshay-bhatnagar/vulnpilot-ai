from pathlib import Path

from backend.scanners.base import ScanExecutionResult, SubprocessScannerAdapter


class BurpScannerAdapter(SubprocessScannerAdapter):
    name = "burp"
    executable_name = "burp"
    supported_scan_types = frozenset({"default", "crawl", "active", "passive"})

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        raise RuntimeError("Burp execution is not configured. Import Burp XML exports through the upload workflow.")
