from datetime import date
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from backend.models.schemas import (
    ReportMetadata,
    ScanAnalysisResponse,
    ScanSummaryMetrics,
    Severity,
    SeverityBreakdown,
    VulnerabilityItem,
)
from backend.services.report_service import ReportService


class ReportServiceTests(unittest.TestCase):
    def test_generates_a_pdf_from_the_latest_normalized_scan(self) -> None:
        service = ReportService()
        service.store_scan(
            ScanAnalysisResponse(
                findings=[
                    VulnerabilityItem(
                        title="Reflected XSS",
                        tool_source="Burp Suite",
                        severity=Severity.HIGH,
                        target_url="https://example.test/search",
                        cwe="CWE-79",
                        owasp_category="A03:2021 - Injection",
                    )
                ],
                summary=ScanSummaryMetrics(
                    total_raw_findings=1,
                    unique_findings=1,
                    deduplicated_count=0,
                    severity_breakdown=SeverityBreakdown(high=1),
                    tools_detected=["Burp Suite"],
                ),
            )
        )

        pdf = service.generate(
            ReportMetadata(
                company_name="Example Corp",
                assessment_date=date.today().isoformat(),
                assessment_scope="example.test",
                assessment_type="Web Application Assessment",
            )
        )

        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertEqual(service.latest_pdf(), pdf)

    def test_generates_and_reads_a_report_from_persisted_ai_results(self) -> None:
        analysis = ScanAnalysisResponse(
            findings=[
                VulnerabilityItem(
                    title="Stored finding",
                    tool_source="Nmap",
                    severity=Severity.LOW,
                    target_url="https://example.test",
                )
            ],
            summary=ScanSummaryMetrics(
                total_raw_findings=1,
                unique_findings=1,
                deduplicated_count=0,
                severity_breakdown=SeverityBreakdown(low=1),
                tools_detected=["Nmap"],
            ),
        )
        with TemporaryDirectory() as directory:
            scan_directory = Path(directory)
            (scan_directory / "ai.json").write_text(analysis.model_dump_json(), encoding="utf-8")
            service = ReportService()
            pdf, report_path = service.generate_scan_report(
                scan_directory,
                ReportMetadata(assessment_date=date.today().isoformat()),
            )

            self.assertEqual(report_path, scan_directory / "report.pdf")
            self.assertTrue(report_path.is_file())
            self.assertEqual(service.scan_pdf(scan_directory), pdf)


if __name__ == "__main__":
    unittest.main()
