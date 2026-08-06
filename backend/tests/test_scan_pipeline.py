import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend.jobs.models import CreateScanJobRequest
from backend.models.schemas import ScanAnalysisResponse, ScanSummaryMetrics, SeverityBreakdown
from backend.scanners.base import ScanExecutionResult, ScannerAdapter
from backend.scanners.scanner_manager import ScannerManager


class FakeNmapAdapter(ScannerAdapter):
    name = "nmap"
    executable_name = "nmap"

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        path = output_dir / "nmap.xml"
        path.write_text("<nmaprun><host><address addr='10.0.0.2' addrtype='ipv4'/><ports><port protocol='tcp' portid='80'><state state='open'/><service name='http'/></port></ports></host></nmaprun>")
        return ScanExecutionResult(path)

    async def cancel_scan(self, job_id: str) -> None:
        return None

    def parse_results(self, raw_results):
        return []

    def normalize(self, parsed_results):
        return []


class FakeNucleiAdapter(FakeNmapAdapter):
    name = "nuclei"
    executable_name = "nuclei"

    async def run_scan(self, job_id: str, target: str, scan_type: str, output_dir: Path, custom_args: list[str]) -> ScanExecutionResult:
        path = output_dir / "nuclei.jsonl"
        path.write_text(json.dumps({"info": {"name": "Exposed panel", "severity": "high"}, "matched-at": "https://example.test/admin"}) + "\n")
        return ScanExecutionResult(path)


class ScanPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_merges_parses_and_runs_ai_once_after_batch(self) -> None:
        with TemporaryDirectory() as directory:
            manager = ScannerManager(storage_root=Path(directory))
            manager.register(FakeNmapAdapter())
            manager.register(FakeNucleiAdapter())
            calls: list[int] = []

            async def fake_process(findings):
                calls.append(len(findings))
                return ScanAnalysisResponse(
                    findings=findings,
                    summary=ScanSummaryMetrics(
                        total_raw_findings=len(findings),
                        unique_findings=len(findings),
                        deduplicated_count=0,
                        severity_breakdown=SeverityBreakdown(),
                        tools_detected=sorted({finding.tool_source for finding in findings}),
                    ),
                )

            with patch("backend.scanners.scanner_manager.process_vulnerabilities", fake_process):
                job = await manager.launch_job(
                    CreateScanJobRequest(
                        scanner="nmap",
                        scanners=["nuclei"],
                        target="example.test",
                        generate_executive_report=True,
                    )
                )
                await manager._tasks[job.job_id]

            completed = manager.get_job(job.job_id)
            self.assertIsNotNone(completed)
            self.assertEqual(completed.status.value, "Completed")
            self.assertEqual(calls, [2])
            self.assertTrue((Path(directory) / job.job_id / "normalized.json").exists())
            self.assertTrue((Path(directory) / job.job_id / "ai.json").exists())
            self.assertTrue((Path(directory) / job.job_id / "report.pdf").exists())
            self.assertEqual(completed.finding_count, 2)
            self.assertIsNotNone(completed.analysis)
            self.assertEqual(completed.report_path, str(Path(directory) / job.job_id / "report.pdf"))


if __name__ == "__main__":
    unittest.main()
