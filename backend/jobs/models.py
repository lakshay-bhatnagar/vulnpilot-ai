"""Typed scan orchestration job contracts."""

from datetime import UTC, datetime
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field

from backend.models.schemas import ScanAnalysisResponse


class ScanJobStatus(str, Enum):
    QUEUED = "Queued"
    RUNNING = "Running"
    PARSING = "Parsing"
    AI_ANALYSIS = "AI Analysis"
    GENERATING_REPORT = "Generating Report"
    COMPLETED = "Completed"
    FAILED = "Failed"
    CANCELLED = "Cancelled"


class CreateScanJobRequest(BaseModel):
    scanner: str = Field(default="nmap", min_length=1, description="Registered scanner adapter name")
    target: str = Field(min_length=1, description="Host, IP address, CIDR, or URL to assess")
    scan_type: str = Field(default="default", min_length=1)
    depth: str = Field(default="standard", min_length=1, description="Requested scan depth")
    scan_profile: str | None = Field(default=None, description="Optional advanced profile; direct scanner jobs remain supported")
    profile_mode: str = Field(default="standard", description="quick, standard, or comprehensive")
    generate_executive_report: bool = Field(default=False, description="Generate report.pdf after AI analysis")
    custom_args: list[str] = Field(default_factory=list, description="Additional scanner arguments")
    scanners: list[str] = Field(default_factory=list, description="Optional scanner batch; scanner remains the backward-compatible primary value")
    project_id: str | None = Field(default=None, description="Optional owning project for historical tracking")


class ScanToolResult(BaseModel):
    scanner: str
    status: str
    finding_count: int = Field(default=0, ge=0)
    raw_output_path: str | None = None
    error_message: str | None = None


class ScanJob(BaseModel):
    job_id: str = Field(default_factory=lambda: str(uuid4()))
    scanner: str
    target: str
    scan_type: str
    project_id: str | None = None
    status: ScanJobStatus = ScanJobStatus.QUEUED
    progress: int = Field(default=0, ge=0, le=100)
    current_phase: str = "Queued for execution"
    current_scanner: str | None = None
    created_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_time: datetime | None = None
    completed_time: datetime | None = None
    duration: float | None = Field(default=None, description="Elapsed job duration in seconds")
    finding_count: int = Field(default=0, ge=0)
    error_message: str | None = None
    raw_output_path: str | None = None
    normalized_output_path: str | None = None
    ai_output_path: str | None = None
    report_path: str | None = None
    scan_profile: str | None = None
    profile_mode: str | None = None
    tool_results: list[ScanToolResult] = Field(default_factory=list)
    source_type: str | None = None
    detected_languages: list[str] = Field(default_factory=list)
    mobile_type: str | None = None
    analysis: ScanAnalysisResponse | None = None
