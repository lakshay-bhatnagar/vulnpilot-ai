import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import zipfile

from backend.scanners.mobile_scanner import mobile_scanner
from backend.services.mobile_ingestion import detect_mobile_type, mobile_ingestion_service


def zip_bytes(*names: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, "fixture")
    return buffer.getvalue()


class MobileIngestionTests(unittest.TestCase):
    def test_detects_apk_from_archive_contents(self) -> None:
        self.assertEqual(detect_mobile_type("app.apk", zip_bytes("AndroidManifest.xml", "classes.dex")), "apk")

    def test_detects_ipa_from_payload_app_contents(self) -> None:
        self.assertEqual(detect_mobile_type("app.ipa", zip_bytes("Payload/App.app/Info.plist")), "ipa")

    def test_android_plan_runs_decompile_static_and_dependency_tools(self) -> None:
        with TemporaryDirectory() as directory:
            package = Path(directory) / "app.apk"
            package.write_bytes(b"APK")
            plan = mobile_scanner.build_plan("apk", package, Path(directory), "standard")
            self.assertEqual(plan.scanners, ("apktool", "jadx", "mobsf", "semgrep", "trivy", "syft", "osv-scanner"))
            self.assertEqual(plan.targets["semgrep"], str(Path(directory) / "jadx-decompiled"))

    def test_ipa_preparation_extracts_static_content(self) -> None:
        with TemporaryDirectory() as directory:
            prepared = mobile_ingestion_service.prepare(Path(directory), "app.ipa", zip_bytes("Payload/App.app/Info.plist"))
            self.assertEqual(prepared.package_type, "ipa")
            self.assertTrue((Path(directory) / "ipa-static" / "Payload" / "App.app" / "Info.plist").is_file())
