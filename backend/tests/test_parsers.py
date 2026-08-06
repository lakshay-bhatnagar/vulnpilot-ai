from pathlib import Path
import unittest

from backend.parsers.factory import get_parser


FIXTURES = Path(__file__).parent / "fixtures"


class ParserFixtureTests(unittest.TestCase):
    def test_burp_xml_fixture(self) -> None:
        content = (FIXTURES / "sample_burp.xml").read_bytes()
        findings = get_parser("sample_burp.xml", content)(content)
        self.assertEqual(findings[0].tool_source, "Burp Suite")
        self.assertEqual(findings[0].severity.value, "High")

    def test_nuclei_json_fixture(self) -> None:
        content = (FIXTURES / "sample_nuclei.json").read_bytes()
        findings = get_parser("sample_nuclei.json", content)(content)
        self.assertEqual(findings[0].tool_source, "Nuclei")
        self.assertEqual(findings[0].target_url, "https://example.test/admin")

    def test_nessus_fixture_and_xml_sniffing(self) -> None:
        content = (FIXTURES / "sample_nessus.nessus").read_bytes()
        findings = get_parser("renamed-export.xml", content)(content)
        finding = findings[0]
        self.assertEqual(finding.tool_source, "Nessus")
        self.assertIn("Plugin 42873", finding.title)
        self.assertEqual(finding.target_url, "tcp://10.0.0.10:443")
        self.assertIn("CVE-2020-0001", finding.raw_evidence or "")


if __name__ == "__main__":
    unittest.main()
