"""JADX APK decompiler runtime integration."""

from pathlib import Path

from backend.scanners.runtime_base import BaseScanner


class JadxScanner(BaseScanner):
    name, executable_name, docker_image, output_filename = "jadx", "jadx", "skylot/jadx:latest", "jadx.json"

    def validate_target(self, target: str) -> None:
        if not Path(target).expanduser().is_file():
            raise ValueError("JADX requires an APK file.")

    def build_local_command(self, executable: str, target: str, scan_type: str, output_path: Path, custom_args: list[str]) -> list[str]:
        return [executable, "-d", str(output_path.parent / "jadx-decompiled"), *custom_args, target]

    def build_docker_arguments(self, target: str, scan_type: str, custom_args: list[str]) -> list[str]:
        return ["-d", "/workspace/output/jadx-decompiled", *custom_args, target]

    def after_execute(self, output_dir: Path, output_path: Path) -> None:
        if not (output_dir / "jadx-decompiled").is_dir():
            raise RuntimeError("JADX completed without producing a decompiled source directory.")
        output_path.write_text('{"output":"jadx-decompiled"}', encoding="utf-8")
