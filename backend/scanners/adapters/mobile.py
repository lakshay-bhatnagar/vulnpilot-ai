"""APK preparation adapters; Frida and Objection can be registered beside these later."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.models.schemas import VulnerabilityItem
from backend.scanners.base import ScanExecutionResult, SubprocessScannerAdapter


class _MobilePreparationAdapter(SubprocessScannerAdapter):
    supported_scan_types = frozenset({"default"})

    def validate_target(self, target: str) -> None:
        if not Path(target).expanduser().is_file():
            raise ValueError(f"{self.name} requires an APK file.")

    def parse_results(self, raw_results: Any) -> list[VulnerabilityItem]:
        return []

    def normalize(self, parsed_results: list[VulnerabilityItem]) -> list[VulnerabilityItem]:
        return parsed_results


class ApktoolScannerAdapter(_MobilePreparationAdapter):
    name, executable_name = "apktool", "apktool"

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        executable = self.executable_path()
        if executable is None:
            raise RuntimeError("APKTool is not installed or not available on PATH.")
        decoded = output_dir / "apktool-decoded"
        await self._run_command(job_id, [executable, "d", "-f", target, "-o", str(decoded)], output_dir)
        if not decoded.is_dir():
            raise RuntimeError("APKTool completed without producing a decoded APK directory.")
        marker = output_dir / "apktool.json"
        marker.write_text('{"output":"apktool-decoded"}', encoding="utf-8")
        return ScanExecutionResult(raw_output_path=marker)


class JadxScannerAdapter(_MobilePreparationAdapter):
    name, executable_name = "jadx", "jadx"

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        executable = self.executable_path()
        if executable is None:
            raise RuntimeError("JADX is not installed or not available on PATH.")
        decompiled = output_dir / "jadx-decompiled"
        await self._run_command(job_id, [executable, "-d", str(decompiled), target], output_dir)
        if not decompiled.is_dir():
            raise RuntimeError("JADX completed without producing a decompiled source directory.")
        marker = output_dir / "jadx.json"
        marker.write_text('{"output":"jadx-decompiled"}', encoding="utf-8")
        return ScanExecutionResult(raw_output_path=marker)
