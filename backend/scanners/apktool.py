"""APKTool decode runtime integration."""

from pathlib import Path

from backend.scanners.runtime_base import BaseScanner


class ApktoolScanner(BaseScanner):
    name, executable_name, docker_image, output_filename = "apktool", "apktool", "openapk/apktool:latest", "apktool.json"

    def validate_target(self, target: str) -> None:
        if not Path(target).expanduser().is_file():
            raise ValueError("APKTool requires an APK file.")

    def build_local_command(self, executable: str, target: str, scan_type: str, output_path: Path, custom_args: list[str]) -> list[str]:
        return [executable, "d", "-f", target, "-o", str(output_path.parent / "apktool-decoded"), *custom_args]

    def build_docker_arguments(self, target: str, scan_type: str, custom_args: list[str]) -> list[str]:
        return ["d", "-f", target, "-o", "/workspace/output/apktool-decoded", *custom_args]

    def after_execute(self, output_dir: Path, output_path: Path) -> None:
        if not (output_dir / "apktool-decoded").is_dir():
            raise RuntimeError("APKTool completed without producing a decoded APK directory.")
        output_path.write_text('{"output":"apktool-decoded"}', encoding="utf-8")
