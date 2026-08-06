"""Mobile package staging and APK/IPA detection for the mobile profile."""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path


@dataclass(frozen=True)
class PreparedMobilePackage:
    package_path: Path
    package_type: str


def detect_mobile_type(filename: str, content: bytes) -> str:
    lower_name = filename.lower()
    if not lower_name.endswith((".apk", ".ipa")):
        raise ValueError("Mobile packages must use the .apk or .ipa extension.")
    if not content.startswith(b"PK\x03\x04"):
        raise ValueError("Mobile package is not a valid ZIP-based APK or IPA archive.")
    try:
        with zipfile.ZipFile(BytesIO(content)) as archive:
            names = archive.namelist()
    except zipfile.BadZipFile as exc:
        raise ValueError("Mobile package is not a valid APK or IPA archive.") from exc
    if any(name == "AndroidManifest.xml" or name == "classes.dex" for name in names):
        return "apk"
    if any(name.startswith("Payload/") and ".app/" in name for name in names):
        return "ipa"
    # Extension fallback supports stripped test artifacts while preserving a
    # strict accepted file-type boundary.
    return "apk" if lower_name.endswith(".apk") else "ipa"


class MobileIngestionService:
    def prepare(self, scan_directory: Path, filename: str, content: bytes) -> PreparedMobilePackage:
        package_type = detect_mobile_type(filename, content)
        scan_directory.mkdir(parents=True, exist_ok=True)
        package_path = scan_directory / f"mobile-app.{package_type}"
        package_path.write_bytes(content)
        return PreparedMobilePackage(package_path, package_type)


mobile_ingestion_service = MobileIngestionService()
