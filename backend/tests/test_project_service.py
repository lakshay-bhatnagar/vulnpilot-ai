from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from backend.models.schemas import ScanAnalysisResponse, ScanSummaryMetrics, Severity, SeverityBreakdown, VulnerabilityItem
from backend.services.project_service import ProjectService


class ProjectServiceTests(unittest.TestCase):
    def _analysis(self, title: str = "SQL injection") -> ScanAnalysisResponse:
        finding = VulnerabilityItem(title=title, tool_source="Nuclei", severity=Severity.HIGH, target_url="https://example.test/search", cwe="CWE-89")
        return ScanAnalysisResponse(findings=[finding], summary=ScanSummaryMetrics(total_raw_findings=1, unique_findings=1, deduplicated_count=0, severity_breakdown=SeverityBreakdown(high=1), tools_detected=["Nuclei"]))

    def test_persists_assets_and_classifies_rescan_findings(self) -> None:
        with TemporaryDirectory() as directory:
            service = ProjectService(Path(directory) / "vulnpilot.db")
            project = service.create_project("Example")
            service.add_asset(project["id"], "domain", "example.test")
            first = service.record_completed_scan(project["id"], None, self._analysis(), scan_type="web", target="example.test")
            second = service.record_completed_scan(project["id"], None, self._analysis(), scan_type="web", target="example.test")

            self.assertEqual(first.new_findings, 1)
            self.assertEqual(second.recurring_findings, 1)
            stored = service.get_project(project["id"])
            self.assertEqual(stored["assets"][0]["value"], "example.test")
            self.assertEqual(stored["open_findings"], 1)

    def test_marks_absent_prior_findings_resolved(self) -> None:
        with TemporaryDirectory() as directory:
            service = ProjectService(Path(directory) / "vulnpilot.db")
            project = service.create_project("Example")
            service.record_completed_scan(project["id"], None, self._analysis(), scan_type="web", target="example.test")
            resolved = service.record_completed_scan(project["id"], None, ScanAnalysisResponse(findings=[], summary=ScanSummaryMetrics(total_raw_findings=0, unique_findings=0, deduplicated_count=0, severity_breakdown=SeverityBreakdown(), tools_detected=[])), scan_type="web", target="example.test")
            self.assertEqual(resolved.resolved_findings, 1)
            self.assertEqual(service.get_project(project["id"])["resolved_findings"], 1)


if __name__ == "__main__":
    unittest.main()
