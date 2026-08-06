"""Safe source-code staging and language detection for SAST jobs."""

from __future__ import annotations

import asyncio
import shutil
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


LANGUAGE_EXTENSIONS = {
    "Python": {".py"}, "Java": {".java"}, "JavaScript": {".js", ".jsx"}, "TypeScript": {".ts", ".tsx"},
    "Go": {".go"}, "C#": {".cs"}, "PHP": {".php"}, "Ruby": {".rb"}, "Kotlin": {".kt", ".kts"},
    "Swift": {".swift"}, "C/C++": {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"},
}
IGNORED_DIRECTORIES = {".git", "node_modules", "vendor", "venv", ".venv", "dist", "build", "target"}


@dataclass(frozen=True)
class PreparedSource:
    directory: Path
    languages: list[str]
    source_type: str


def detect_languages(directory: Path) -> list[str]:
    found: set[str] = set()
    for path in directory.rglob("*"):
        if any(part in IGNORED_DIRECTORIES for part in path.parts) or not path.is_file():
            continue
        for language, extensions in LANGUAGE_EXTENSIONS.items():
            if path.suffix.lower() in extensions:
                found.add(language)
    return sorted(found)


def _safe_extract_path(destination: Path, member_name: str) -> Path:
    resolved = (destination / member_name).resolve()
    if not resolved.is_relative_to(destination.resolve()):
        raise ValueError("Archive contains an unsafe path.")
    return resolved


class SourceIngestionService:
    async def prepare(self, scan_directory: Path, *, archive_name: str | None = None, archive_content: bytes | None = None, repository_url: str | None = None, local_path: str | None = None) -> PreparedSource:
        scan_directory.mkdir(parents=True, exist_ok=True)
        if archive_name and archive_content is not None:
            source = scan_directory / "source"
            source.mkdir(exist_ok=True)
            archive_path = scan_directory / f"source-upload{''.join(Path(archive_name).suffixes)}"
            archive_path.write_bytes(archive_content)
            self._extract_archive(archive_path, source)
            return PreparedSource(self._project_root(source), detect_languages(source), "archive")
        if repository_url:
            source = scan_directory / "source"
            await self._clone(repository_url, source)
            return PreparedSource(source, detect_languages(source), "git")
        if local_path:
            source = Path(local_path).expanduser().resolve()
            if not source.is_dir():
                raise ValueError("Local source path must be an existing directory on the backend host.")
            return PreparedSource(source, detect_languages(source), "local")
        raise ValueError("Provide a ZIP/TAR archive, Git repository URL, or local source directory.")

    def _extract_archive(self, archive_path: Path, destination: Path) -> None:
        lower = archive_path.name.lower()
        if lower.endswith(".zip"):
            with zipfile.ZipFile(archive_path) as archive:
                for member in archive.infolist():
                    _safe_extract_path(destination, member.filename)
                archive.extractall(destination)
            return
        if lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
            with tarfile.open(archive_path) as archive:
                for member in archive.getmembers():
                    _safe_extract_path(destination, member.name)
                archive.extractall(destination, filter="data")
            return
        raise ValueError("Source archives must be ZIP, TAR, TAR.GZ, TGZ, TAR.BZ2, or TAR.XZ.")

    async def _clone(self, repository_url: str, destination: Path) -> None:
        parsed = urlparse(repository_url)
        if (parsed.scheme not in {"https", "http", "ssh"} and not repository_url.startswith("git@")) or any(character.isspace() for character in repository_url):
            raise ValueError("Repository URL must be a valid HTTP(S) or SSH Git URL.")
        executable = shutil.which("git")
        if executable is None:
            raise RuntimeError("Git is not installed or not available on PATH.")
        process = await asyncio.create_subprocess_exec(executable, "clone", "--depth", "1", repository_url, str(destination), stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"Git clone failed: {(stderr or b'').decode('utf-8', errors='replace')[:500]}")

    @staticmethod
    def _project_root(source: Path) -> Path:
        children = [child for child in source.iterdir() if child.name != "__MACOSX"]
        return children[0] if len(children) == 1 and children[0].is_dir() else source


source_ingestion_service = SourceIngestionService()
