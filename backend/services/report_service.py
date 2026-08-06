"""Portable executive-report generation service (PDF today, DOCX renderer later)."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Protocol

from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from backend.models.schemas import ReportMetadata, ScanAnalysisResponse, ScanSummaryMetrics, Severity, SeverityBreakdown, VulnerabilityItem


class ReportRenderer(Protocol):
    """Renderer boundary that permits a DOCX implementation later."""

    def render(self, analysis: ScanAnalysisResponse, metadata: ReportMetadata) -> bytes: ...


SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
SEVERITY_COLOURS = {
    Severity.CRITICAL: colors.HexColor("#B91C1C"),
    Severity.HIGH: colors.HexColor("#C2410C"),
    Severity.MEDIUM: colors.HexColor("#A16207"),
    Severity.LOW: colors.HexColor("#0369A1"),
}
NAVY = colors.HexColor("#0B1220")
CYAN = colors.HexColor("#0891B2")
SLATE = colors.HexColor("#475569")


def _safe(value: str | None, fallback: str = "Not available") -> str:
    return value if value and value.strip() else fallback


def _risk_score(analysis: ScanAnalysisResponse) -> float:
    counts = analysis.summary.severity_breakdown
    weighted = counts.critical * 10 + counts.high * 7.5 + counts.medium * 5 + counts.low * 2.5
    return round(min(10, weighted / max(analysis.summary.unique_findings, 1)), 1)


def _counter(findings: list[VulnerabilityItem], selector) -> Counter[str]:
    return Counter(value for finding in findings if (value := selector(finding)))


class PdfExecutiveReportRenderer:
    """ReportLab implementation for enterprise-style executive reports."""

    def __init__(self) -> None:
        styles = getSampleStyleSheet()
        self.title = ParagraphStyle("VPTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=29, leading=35, textColor=NAVY, alignment=TA_CENTER)
        self.heading = ParagraphStyle("VPHeading", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=17, leading=22, spaceBefore=16, spaceAfter=9, textColor=NAVY)
        self.subheading = ParagraphStyle("VPSubheading", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=16, spaceBefore=10, spaceAfter=5, textColor=NAVY)
        self.body = ParagraphStyle("VPBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.8, leading=12, spaceAfter=5, textColor=colors.HexColor("#1E293B"))
        self.small = ParagraphStyle("VPSmall", parent=self.body, fontSize=7.5, leading=10, textColor=SLATE)
        self.cover = ParagraphStyle("VPCover", parent=self.body, fontSize=12, leading=18, alignment=TA_CENTER, textColor=SLATE)

    def _p(self, text: str, style: ParagraphStyle | None = None) -> Paragraph:
        escaped = (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return Paragraph(escaped.replace("\n", "<br/>"), style or self.body)

    def _table(self, rows: list[list[object]], widths: list[float] | None = None) -> Table:
        table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("LEADING", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ]))
        return table

    def _chart(self, title: str, data: Counter[str], pie: bool = False) -> Drawing:
        drawing = Drawing(460, 190)
        drawing.add(String(8, 173, title, fontName="Helvetica-Bold", fontSize=10, fillColor=NAVY))
        labels = list(data)[:8] or ["No data"]
        values = [data[label] for label in labels] or [1]
        if pie:
            chart = Pie()
            chart.x, chart.y, chart.width, chart.height = 55, 5, 145, 145
            chart.data, chart.labels = values, labels
            chart.slices.strokeWidth = 0.5
            for index, colour in enumerate((colors.HexColor("#B91C1C"), colors.HexColor("#C2410C"), colors.HexColor("#A16207"), colors.HexColor("#0369A1"), CYAN)):
                if index < len(values):
                    chart.slices[index].fillColor = colour
            drawing.add(chart)
        else:
            chart = HorizontalBarChart()
            chart.x, chart.y, chart.width, chart.height = 145, 15, 285, 135
            chart.data = [values]
            chart.categoryAxis.categoryNames = labels
            chart.categoryAxis.labels.fontSize = 6.5
            chart.valueAxis.labels.fontSize = 6.5
            chart.valueAxis.valueMin = 0
            chart.valueAxis.valueMax = max(values) + 1
            chart.bars[0].fillColor = CYAN
            drawing.add(chart)
        return drawing

    def _header_footer(self, canvas, document) -> None:
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
        canvas.line(1.6 * cm, 1.45 * cm, A4[0] - 1.6 * cm, 1.45 * cm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(SLATE)
        canvas.drawString(1.6 * cm, 0.95 * cm, "VulnPilot AI - Confidential Security Assessment")
        canvas.drawRightString(A4[0] - 1.6 * cm, 0.95 * cm, f"Page {document.page}")
        canvas.restoreState()

    def render(self, analysis: ScanAnalysisResponse, metadata: ReportMetadata) -> bytes:
        buffer = BytesIO()
        document = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=1.6 * cm, leftMargin=1.6 * cm, topMargin=1.7 * cm, bottomMargin=2 * cm, title="VulnPilot Executive Security Report")
        findings = analysis.findings
        severity = Counter(finding.severity.value for finding in findings)
        owasp = _counter(findings, lambda item: item.owasp_category or "Unmapped")
        cwe = _counter(findings, lambda item: item.cwe or "Unmapped")
        mitre = _counter(findings, lambda item: item.mitre_attack or "Unmapped")
        capec = _counter(findings, lambda item: item.capec or "Unmapped")
        assets = _counter(findings, lambda item: item.target_url)
        scanners = _counter(findings, lambda item: item.tool_source)
        story: list[object] = []

        story += [Spacer(1, 3.5 * cm), self._p("EXECUTIVE SECURITY ASSESSMENT", self.title), Spacer(1, 0.7 * cm), self._p(metadata.company_name, ParagraphStyle("Company", parent=self.cover, fontName="Helvetica-Bold", fontSize=16, textColor=CYAN)), Spacer(1, 1.4 * cm)]
        cover_rows = [[self._p("Assessment date", self.small), self._p(metadata.assessment_date, self.body)], [self._p("Assessment scope", self.small), self._p(metadata.assessment_scope, self.body)], [self._p("Assessment type", self.small), self._p(metadata.assessment_type, self.body)], [self._p("Generated by", self.small), self._p("VulnPilot AI", self.body)], [self._p("Classification", self.small), self._p(metadata.classification, self.body)], [self._p("Generated", self.small), self._p(datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"), self.body)]]
        cover_table = Table(cover_rows, colWidths=[4.2 * cm, 11 * cm])
        cover_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E0F2FE")), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#BAE6FD")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 7)]))
        story += [cover_table, Spacer(1, 2 * cm), self._p("Prepared by VulnPilot AI", self.cover), PageBreak()]

        score = _risk_score(analysis)
        ai_summary = "AI correlation normalized scanner output, deduplicated related observations, and attached OWASP, CWE, MITRE ATT&CK, CAPEC, remediation, and proof-of-concept guidance."
        story += [self._p("Executive Summary", self.heading), self._p(f"The assessment identified {analysis.summary.total_raw_findings} raw observations consolidated into {analysis.summary.unique_findings} unique findings. The overall risk score is {score}/10."), self._p("AI Summary", self.subheading), self._p(ai_summary), self._table([[self._p("Overall risk score", self.small), self._p("Critical", self.small), self._p("High", self.small), self._p("Medium", self.small), self._p("Low", self.small), self._p("Deduplicated", self.small)], [self._p(f"{score}/10", self.body), self._p(str(severity["Critical"]), self.body), self._p(str(severity["High"]), self.body), self._p(str(severity["Medium"]), self.body), self._p(str(severity["Low"]), self.body), self._p(str(analysis.summary.deduplicated_count), self.body)]])]
        story += [self._p("Affected Assets", self.heading), self._table([[self._p("Asset", self.small), self._p("Findings", self.small)]] + [[self._p(asset), self._p(str(count))] for asset, count in assets.most_common(12)], [13 * cm, 3 * cm])]
        story += [
            self._p("Risk and Coverage Charts", self.heading),
            self._chart("Severity Distribution", severity, pie=True),
            PageBreak(),
        ]
        for title, chart_data in (
            ("OWASP Categories", owasp),
            ("Top CWE", cwe),
            ("Most Affected Assets", assets),
            ("Scanner Breakdown", scanners),
        ):
            story += [self._p("Risk and Coverage Charts", self.heading), self._chart(title, chart_data), PageBreak()]

        story += [self._p("OWASP, CWE, MITRE ATT&CK and CAPEC Mapping", self.heading)]
        for label, values in (("OWASP", owasp), ("CWE", cwe), ("MITRE ATT&CK", mitre), ("CAPEC", capec)):
            story += [self._p(label, self.subheading), self._table([[self._p(label, self.small), self._p("Findings", self.small)]] + [[self._p(key), self._p(str(value))] for key, value in values.most_common(15)], [13 * cm, 3 * cm])]
        story.append(PageBreak())

        story.append(self._p("Vulnerability Details", self.heading))
        sorted_findings = sorted(findings, key=lambda finding: SEVERITY_ORDER.index(finding.severity))
        for number, finding in enumerate(sorted_findings, 1):
            colour = SEVERITY_COLOURS[finding.severity]
            details = [[self._p("Field", self.small), self._p("Details", self.small)], [self._p("Severity"), self._p(finding.severity.value)], [self._p("CVSS"), self._p(_safe(finding.cvss))], [self._p("Affected asset / URL"), self._p(finding.target_url)], [self._p("OWASP / CWE / CVE"), self._p(" / ".join((_safe(finding.owasp_category), _safe(finding.cwe), _safe(finding.cve))))], [self._p("CAPEC / MITRE ATT&CK"), self._p(" / ".join((_safe(finding.capec), _safe(finding.mitre_attack))))], [self._p("Risk description and evidence"), self._p(_safe(finding.raw_evidence))], [self._p("Business impact"), self._p(_safe(finding.raw_evidence, "Impact requires validation with the system owner."))], [self._p("Steps to reproduce"), self._p(_safe(finding.request_payload))], [self._p("Proof of concept"), self._p(_safe(finding.generated_poc))], [self._p("Recommended fix"), self._p(_safe(finding.remediation))], [self._p("Secure code example"), self._p(_safe(finding.secure_code_fix))], [self._p("References"), self._p(", ".join(finding.references) or "Not available")], [self._p("Screenshot"), self._p("Screenshot placeholder - attach validated reproduction evidence here.")]]
            block = [self._p(f"{number:02d}. {finding.title}", self.subheading), self._table(details, [4 * cm, 12 * cm]), Spacer(1, 0.45 * cm)]
            story.append(KeepTogether(block))
        story.append(PageBreak())

        raw_count = analysis.summary.total_raw_findings
        story += [self._p("Appendix", self.heading), self._p("Scan Metadata", self.subheading), self._table([[self._p("Metric", self.small), self._p("Value", self.small)], [self._p("Raw findings"), self._p(str(raw_count))], [self._p("Deduplicated findings"), self._p(str(analysis.summary.deduplicated_count))], [self._p("Unique findings"), self._p(str(analysis.summary.unique_findings))], [self._p("Scanner sources"), self._p(", ".join(analysis.summary.tools_detected))], [self._p("Scanner versions"), self._p("Not available from uploaded artifacts")], [self._p("AI model used"), self._p("Configured OpenRouter analysis model")], [self._p("Report generation timestamp"), self._p(datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"))]]), self._p("Raw and Deduplicated Finding Index", self.subheading), self._table([[self._p("#", self.small), self._p("Finding", self.small), self._p("Source", self.small), self._p("Severity", self.small)]] + [[self._p(str(index)), self._p(finding.title), self._p(finding.tool_source), self._p(finding.severity.value)] for index, finding in enumerate(sorted_findings, 1)], [1 * cm, 8.5 * cm, 3.5 * cm, 3 * cm])]

        document.build(story, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
        return buffer.getvalue()


@dataclass
class LatestReport:
    pdf: bytes
    metadata: ReportMetadata
    created_at: datetime


class ReportService:
    def __init__(self, renderer: ReportRenderer | None = None) -> None:
        self._renderer = renderer or PdfExecutiveReportRenderer()
        self._latest_analysis: ScanAnalysisResponse | None = None
        self._latest_report: LatestReport | None = None
        self._latest_scan_directory: Path | None = None

    def store_scan(self, analysis: ScanAnalysisResponse) -> None:
        self._latest_analysis = analysis
        self._latest_scan_directory = None

    def generate(self, metadata: ReportMetadata) -> bytes:
        if self._latest_analysis is None:
            raise ValueError("No completed scan is available. Upload and analyze a scan before generating a report.")
        pdf = self._render(self._latest_analysis, metadata)
        if self._latest_scan_directory is not None:
            (self._latest_scan_directory / "report.pdf").write_bytes(pdf)
        return pdf

    def generate_scan_report(self, scan_directory: Path, metadata: ReportMetadata) -> tuple[bytes, Path]:
        """Render persisted scan results without rerunning a scanner or the AI engine."""
        analysis = self._load_stored_analysis(scan_directory)
        self._latest_scan_directory = scan_directory
        pdf = self._render(analysis, metadata)
        report_path = scan_directory / "report.pdf"
        report_path.write_bytes(pdf)
        return pdf, report_path

    def scan_pdf(self, scan_directory: Path) -> bytes:
        report_path = scan_directory / "report.pdf"
        if not report_path.is_file():
            raise ValueError("No report has been generated for this scan yet.")
        return report_path.read_bytes()

    def _render(self, analysis: ScanAnalysisResponse, metadata: ReportMetadata) -> bytes:
        pdf = self._renderer.render(analysis, metadata)
        self._latest_analysis = analysis
        self._latest_report = LatestReport(pdf, metadata, datetime.now(UTC))
        return pdf

    def _load_stored_analysis(self, scan_directory: Path) -> ScanAnalysisResponse:
        ai_path = scan_directory / "ai.json"
        if ai_path.is_file():
            try:
                return ScanAnalysisResponse.model_validate_json(ai_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ValueError(f"Stored AI analysis could not be read: {exc}") from exc

        # This fallback keeps report generation deterministic if a completed
        # scan only has normalized findings. It intentionally does not call AI.
        normalized_path = scan_directory / "normalized.json"
        if not normalized_path.is_file():
            raise ValueError("This scan has no stored normalized or AI analysis results.")
        try:
            findings = [VulnerabilityItem.model_validate(item) for item in json.loads(normalized_path.read_text(encoding="utf-8"))]
        except (OSError, ValueError, TypeError) as exc:
            raise ValueError(f"Stored normalized findings could not be read: {exc}") from exc
        severity = SeverityBreakdown(
            critical=sum(item.severity == Severity.CRITICAL for item in findings),
            high=sum(item.severity == Severity.HIGH for item in findings),
            medium=sum(item.severity == Severity.MEDIUM for item in findings),
            low=sum(item.severity == Severity.LOW for item in findings),
        )
        return ScanAnalysisResponse(
            findings=findings,
            summary=ScanSummaryMetrics(
                total_raw_findings=len(findings),
                unique_findings=len(findings),
                deduplicated_count=0,
                severity_breakdown=severity,
                tools_detected=sorted({item.tool_source for item in findings}),
            ),
        )

    def latest_pdf(self) -> bytes:
        if self._latest_report is None:
            raise ValueError("No report has been generated yet.")
        return self._latest_report.pdf


report_service = ReportService()
