import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from backend.parsers.semgrep_parser import parse_semgrep_json
from backend.services.source_ingestion import detect_languages


class SastTests(unittest.TestCase):
    def test_semgrep_json_maps_to_vulnerability_item(self) -> None:
        payload = {
            "results": [{
                "check_id": "python.lang.security.audit.eval-detected",
                "path": "src/app.py",
                "start": {"line": 18},
                "extra": {
                    "message": "Avoid eval on untrusted data.",
                    "severity": "ERROR",
                    "lines": "value = eval(user_input)",
                    "fix": "value = ast.literal_eval(user_input)",
                    "metadata": {"cwe": ["CWE-95"], "owasp": "A03:2021 - Injection", "remediation": "Use a safe parser."},
                },
            }],
        }
        findings = parse_semgrep_json(json.dumps(payload).encode())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe, "CWE-95")
        self.assertEqual(findings[0].owasp_category, "A03:2021 - Injection")
        self.assertEqual(findings[0].target_url, "file://src/app.py#L18")
        self.assertEqual(findings[0].secure_code_fix, "value = ast.literal_eval(user_input)")

    def test_detects_supported_project_languages(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("print('ok')")
            (root / "client.ts").write_text("export {}")
            (root / "service.go").write_text("package main")
            self.assertEqual(detect_languages(root), ["Go", "Python", "TypeScript"])

