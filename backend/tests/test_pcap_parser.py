from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scapy.all import IP, TCP, Raw
from scapy.utils import PcapNgWriter, PcapWriter

from backend.parsers.factory import get_parser


class PcapParserTests(unittest.TestCase):
    @staticmethod
    def _packet():
        return (
            IP(src="10.0.0.5", dst="198.51.100.10")
            / TCP(sport=51515, dport=80)
            / Raw(load=b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n")
        )

    def test_detects_cleartext_basic_auth_and_internal_ip(self) -> None:
        with TemporaryDirectory() as directory:
            capture = Path(directory) / "sample.pcap"
            writer = PcapWriter(str(capture), sync=True)
            writer.write(self._packet())
            writer.close()
            content = capture.read_bytes()

        findings = get_parser("sample.pcap", content)(content)
        titles = {finding.title for finding in findings}
        self.assertIn("HTTP Basic Authentication Sent in Cleartext", titles)
        self.assertIn("Internal IP Address Discovery", titles)

    def test_accepts_pcapng(self) -> None:
        with TemporaryDirectory() as directory:
            capture = Path(directory) / "sample.pcapng"
            writer = PcapNgWriter(str(capture))
            writer.write(self._packet())
            writer.close()
            content = capture.read_bytes()

        # Content signature detection also supports captures whose filename was changed.
        findings = get_parser("renamed-capture.bin", content)(content)
        self.assertTrue(findings)


if __name__ == "__main__":
    unittest.main()
