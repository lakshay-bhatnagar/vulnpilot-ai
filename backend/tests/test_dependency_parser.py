import json
import unittest

from backend.parsers.dependency_parser import parse_trivy_json


class DependencyParserTests(unittest.TestCase):
    def test_maps_trivy_dependency_cve_and_upgrade_data(self) -> None:
        payload = {
            "Results": [{"Target": "requirements.txt", "Vulnerabilities": [{
                "PkgName": "requests", "InstalledVersion": "2.19.0", "FixedVersion": "2.31.0",
                "VulnerabilityID": "CVE-2018-18074", "Severity": "HIGH", "CVSS": {"nvd": {"V3Score": 7.5}},
                "Description": "Credentials may leak on redirect.", "References": ["https://nvd.nist.gov/vuln/detail/CVE-2018-18074"],
            }]}],
        }
        findings = parse_trivy_json(json.dumps(payload).encode())
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.package_name, "requests")
        self.assertEqual(finding.installed_version, "2.19.0")
        self.assertEqual(finding.fixed_version, "2.31.0")
        self.assertEqual(finding.cve, "CVE-2018-18074")
        self.assertEqual(finding.cvss, "7.5")
        self.assertEqual(finding.affected_file, "requirements.txt")

