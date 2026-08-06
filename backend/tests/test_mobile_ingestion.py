import io
import unittest
import zipfile

from backend.services.mobile_ingestion import detect_mobile_type


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

