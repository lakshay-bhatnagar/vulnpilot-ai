"""Scanner registry and safe background execution orchestration."""

from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime
from pathlib import Path

from backend.jobs.manager import ScanJobManager
from backend.jobs.models import CreateScanJobRequest, ScanJob, ScanJobStatus, ScanToolResult
from backend.models.schemas import ReportMetadata, ScanAnalysisMetadata
from backend.scanners.adapters import (
    BurpScannerAdapter,
    MobSFScannerAdapter,
    NessusScannerAdapter,
    NmapScannerAdapter,
    NucleiScannerAdapter,
    SubfinderScannerAdapter,
    AmassScannerAdapter,
    DNSxScannerAdapter,
    HTTPXScannerAdapter,
    NaabuScannerAdapter,
    KatanaScannerAdapter,
    HakrawlerScannerAdapter,
    ArjunScannerAdapter,
    SemgrepScannerAdapter,
    SyftScannerAdapter,
    TrivyScannerAdapter,
    OsvScannerAdapter,
    ApktoolScannerAdapter,
    JadxScannerAdapter,
)
from backend.scanners.base import ScanExecutionResult, ScannerAdapter
from backend.scanners.profiles import resolve_profile
from backend.services.ai_engine import process_vulnerabilities
from backend.services.report_service import report_service
from backend.services.scan_pipeline import deduplicate_findings, parse_scanner_output, write_json
from backend.services.source_ingestion import source_ingestion_service
from backend.services.mobile_ingestion import mobile_ingestion_service
from backend.services.project_service import project_service
from backend.scanner_runtime.tool_registry import build_default_registry
from backend.scanners.mobile_scanner import mobile_scanner


class ScannerManager:
    def __init__(self, job_manager: ScanJobManager | None = None, storage_root: Path | None = None) -> None:
        self._job_manager = job_manager or ScanJobManager()
        self._storage_root = storage_root or Path("storage/scans")
        self._scanners: dict[str, ScannerAdapter] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._active_scanners: dict[str, list[ScannerAdapter]] = {}
        self._runtime_registry = build_default_registry()

    def register(self, scanner: ScannerAdapter) -> None:
        key = scanner.name.lower()
        if key in self._scanners:
            raise ValueError(f"Scanner '{scanner.name}' is already registered.")
        self._scanners[key] = scanner

    async def launch_job(self, request: CreateScanJobRequest) -> ScanJob:
        if request.project_id:
            project_service.get_project(request.project_id)
        profile_name = request.scan_profile.lower() if request.scan_profile else None
        if profile_name and profile_name != "custom_scan":
            scanner_names = list(resolve_profile(profile_name, request.profile_mode))
        else:
            scanner_names = list(dict.fromkeys([request.scanner, *request.scanners]))
        scanners: list[ScannerAdapter] = []
        for scanner_name in scanner_names:
            scanner = self._scanners.get(scanner_name.lower())
            if scanner is None:
                raise ValueError(f"Unknown scanner '{scanner_name}'. Available: {', '.join(self._scanners)}.")
            scanner.validate_target(request.target)
            if profile_name in {None, "custom_scan"} and not scanner.supports_scan_type(request.scan_type):
                raise ValueError(f"Scanner '{scanner.name}' does not support scan type '{request.scan_type}'.")
            scanners.append(scanner)
        if any(not argument or "\x00" in argument for argument in request.custom_args):
            raise ValueError("Custom scanner arguments must be non-empty and cannot contain null bytes.")
        job = self._job_manager.create(request.model_copy(update={"scanner": ", ".join(scanner.name for scanner in scanners)}))
        job = self._job_manager.update(job.job_id, scan_profile=profile_name, profile_mode=request.profile_mode if profile_name else None) or job
        self._active_scanners[job.job_id] = scanners
        self._tasks[job.job_id] = asyncio.create_task(self._execute(job.job_id, scanners, request))
        return job

    async def launch_source_code_job(
        self,
        request: CreateScanJobRequest,
        *,
        archive_name: str | None = None,
        archive_content: bytes | None = None,
        repository_url: str | None = None,
        local_path: str | None = None,
    ) -> ScanJob:
        return await self.launch_project_scan_job(
            request, profile_name="source_code_assessment", archive_name=archive_name, archive_content=archive_content,
            repository_url=repository_url, local_path=local_path,
        )

    async def launch_dependency_scan_job(
        self,
        request: CreateScanJobRequest,
        *,
        archive_name: str | None = None,
        archive_content: bytes | None = None,
        repository_url: str | None = None,
        local_path: str | None = None,
    ) -> ScanJob:
        return await self.launch_project_scan_job(
            request, profile_name="software_composition_analysis", archive_name=archive_name, archive_content=archive_content,
            repository_url=repository_url, local_path=local_path,
        )

    async def launch_project_scan_job(
        self,
        request: CreateScanJobRequest,
        *,
        profile_name: str,
        archive_name: str | None = None,
        archive_content: bytes | None = None,
        repository_url: str | None = None,
        local_path: str | None = None,
    ) -> ScanJob:
        """Stage source material once, then run a profile of pluggable code/dependency engines."""
        if request.project_id:
            project_service.get_project(request.project_id)
        scanners: list[ScannerAdapter] = []
        for scanner_name in resolve_profile(profile_name, request.profile_mode):
            scanner = self._scanners.get(scanner_name)
            if scanner is None:
                raise ValueError(f"Scanner '{scanner_name}' is not registered.")
            scanners.append(scanner)
        project_request = request.model_copy(update={"scanner": ", ".join(scanner.name for scanner in scanners), "scan_profile": profile_name, "scan_type": "default"})
        job = self._job_manager.create(project_request)
        self._job_manager.update(job.job_id, scan_profile=profile_name, profile_mode=request.profile_mode)
        self._active_scanners[job.job_id] = scanners
        self._tasks[job.job_id] = asyncio.create_task(
            self._prepare_and_execute_source(
                job.job_id, scanners, project_request, archive_name, archive_content, repository_url, local_path,
            )
        )
        return self.get_job(job.job_id) or job

    async def launch_mobile_job(self, request: CreateScanJobRequest, *, filename: str, content: bytes) -> ScanJob:
        """Stage an APK/IPA and run the mobile pipeline without coupling future dynamic tools."""
        if request.project_id:
            project_service.get_project(request.project_id)
        job = self._job_manager.create(request.model_copy(update={"scan_profile": "mobile_assessment"}))
        self._job_manager.update(job.job_id, scan_profile="mobile_assessment", profile_mode=request.profile_mode)
        self._tasks[job.job_id] = asyncio.create_task(self._prepare_and_execute_mobile(job.job_id, request, filename, content))
        return self.get_job(job.job_id) or job

    async def _prepare_and_execute_mobile(self, job_id: str, request: CreateScanJobRequest, filename: str, content: bytes) -> None:
        output_dir = self._storage_root / job_id
        try:
            self._job_manager.update(job_id, status=ScanJobStatus.RUNNING, progress=2, current_phase="Detecting and staging mobile package")
            prepared = mobile_ingestion_service.prepare(output_dir, filename, content)
            plan = mobile_scanner.build_plan(prepared.package_type, prepared.package_path, output_dir, request.profile_mode)
            scanners = [self._scanners[name] for name in plan.scanners if name in self._scanners]
            if not scanners:
                raise RuntimeError("No mobile scanner adapters are registered.")
            self._active_scanners[job_id] = scanners
            self._job_manager.update(
                job_id,
                progress=8,
                current_phase=f"Detected {prepared.package_type.upper()} package",
                mobile_type=prepared.package_type,
                scanner=", ".join(scanner.name for scanner in scanners),
                source_type="mobile-package",
            )
            await self._execute(job_id, scanners, request, execution_target=str(prepared.package_path), execution_targets=plan.targets)
        except (RuntimeError, ValueError, PermissionError, OSError) as exc:
            completed = datetime.now(UTC)
            self._job_manager.update(job_id, status=ScanJobStatus.FAILED, progress=100, current_phase="Mobile package preparation failed", completed_time=completed, error_message=str(exc), raw_output_path=str(output_dir))
            self._tasks.pop(job_id, None)
            self._active_scanners.pop(job_id, None)

    async def _prepare_and_execute_source(
        self,
        job_id: str,
        scanners: list[ScannerAdapter],
        request: CreateScanJobRequest,
        archive_name: str | None,
        archive_content: bytes | None,
        repository_url: str | None,
        local_path: str | None,
    ) -> None:
        output_dir = self._storage_root / job_id
        try:
            self._job_manager.update(job_id, status=ScanJobStatus.RUNNING, progress=2, current_phase="Staging project source", current_scanner=scanners[0].name)
            prepared = await source_ingestion_service.prepare(output_dir, archive_name=archive_name, archive_content=archive_content, repository_url=repository_url, local_path=local_path)
            self._job_manager.update(job_id, progress=8, current_phase=f"Detected languages: {', '.join(prepared.languages) or 'unknown'}", source_type=prepared.source_type, detected_languages=prepared.languages)
            await self._execute(job_id, scanners, request, execution_target=str(prepared.directory))
        except (RuntimeError, ValueError, PermissionError, OSError) as exc:
            completed = datetime.now(UTC)
            self._job_manager.update(job_id, status=ScanJobStatus.FAILED, progress=100, current_phase="Source preparation failed", completed_time=completed, error_message=str(exc), raw_output_path=str(output_dir))
            self._tasks.pop(job_id, None)
            self._active_scanners.pop(job_id, None)

    async def _execute(self, job_id: str, scanners: list[ScannerAdapter], request: CreateScanJobRequest, execution_target: str | None = None, execution_targets: dict[str, str] | None = None) -> None:
        started = datetime.now(UTC)
        self._job_manager.update(
            job_id,
            status=ScanJobStatus.RUNNING,
            progress=10,
            current_phase="Executing scanners",
            started_time=started,
            error_message=None,
        )
        try:
            output_dir = self._storage_root / job_id
            output_dir.mkdir(parents=True, exist_ok=True)
            results: list[tuple[ScannerAdapter, ScanExecutionResult]] = []
            tool_results: list[ScanToolResult] = []
            total_scanners = len(scanners)
            for index, scanner in enumerate(scanners, start=1):
                tool_results.append(ScanToolResult(scanner=scanner.name, status="Running"))
                self._job_manager.update(
                    job_id,
                    status=ScanJobStatus.RUNNING,
                    progress=10 + int(35 * (index - 1) / total_scanners),
                    current_scanner=scanner.name,
                    current_phase=(f"{mobile_scanner.phase_for(scanner.name)} ({index}/{total_scanners})" if request.scan_profile == "mobile_assessment" else f"Running {scanner.name} ({index}/{total_scanners})"),
                    tool_results=tool_results,
                )
                try:
                    tool_args = request.custom_args if scanner.name in {"nmap", "nuclei"} else []
                    scanner_target = (execution_targets or {}).get(scanner.name, execution_target or request.target)
                    scan_type = "default" if request.scan_profile else request.scan_type
                    try:
                        runtime_scanner = self._runtime_registry.get(scanner.name)
                        runtime_health = await runtime_scanner.health_check()
                    except ValueError:
                        runtime_scanner, runtime_health = None, {"docker_available": False}
                    if scanner.executable_path() is None and runtime_scanner is not None and runtime_health["docker_available"]:
                        self._job_manager.update(job_id, current_phase=f"Launching {scanner.name.title()} container...", current_scanner=scanner.name, tool_results=tool_results)
                        runtime_output = await runtime_scanner.run(job_id, scanner_target, scan_type, output_dir, tool_args)
                        result = ScanExecutionResult(raw_output_path=runtime_output)
                    else:
                        result = await scanner.run_scan(job_id, scanner_target, scan_type, output_dir, tool_args)
                    tool_results[-1] = ScanToolResult(scanner=scanner.name, status="Completed", raw_output_path=str(result.raw_output_path))
                    results.append((scanner, result))
                except (RuntimeError, ValueError) as exc:
                    missing_binary = "not installed" in str(exc).lower() or "not found on path" in str(exc).lower()
                    tool_results[-1] = ScanToolResult(scanner=scanner.name, status="Skipped" if missing_binary else "Failed", error_message=str(exc))
                    self._job_manager.update(
                        job_id,
                        progress=10 + int(35 * index / total_scanners),
                        current_phase=f"{scanner.name} {'skipped' if missing_binary else 'failed'} ({index}/{total_scanners})",
                        tool_results=tool_results,
                    )
                    continue
                self._job_manager.update(
                    job_id,
                    progress=10 + int(35 * index / total_scanners),
                    current_phase=(f"{mobile_scanner.phase_for(scanner.name)} completed ({index}/{total_scanners})" if request.scan_profile == "mobile_assessment" else f"{scanner.name} completed ({index}/{total_scanners})"),
                    tool_results=tool_results,
                )

            if not results:
                details = "; ".join(f"{item.scanner}: {item.error_message}" for item in tool_results if item.error_message)
                raise RuntimeError(f"No configured scanner completed successfully. {details}")

            self._job_manager.update(job_id, status=ScanJobStatus.PARSING, progress=50, current_scanner=None, current_phase="Parsing scanner outputs")
            normalized = []
            for index, (scanner, result) in enumerate(results, start=1):
                self._job_manager.update(
                    job_id,
                    progress=50 + int(20 * (index - 1) / len(results)),
                    current_scanner=scanner.name,
                    current_phase=f"Parsing {scanner.name} output ({index}/{len(results)})",
                )
                try:
                    parsed = parse_scanner_output(scanner.name, result.raw_output_path)
                    normalized.extend(parsed)
                    tool_position = next(position for position, item in enumerate(tool_results) if item.scanner == scanner.name)
                    tool_results[tool_position] = tool_results[tool_position].model_copy(update={"finding_count": len(parsed)})
                except (OSError, ValueError) as exc:
                    tool_position = next(position for position, item in enumerate(tool_results) if item.scanner == scanner.name)
                    tool_results[tool_position] = tool_results[tool_position].model_copy(update={"status": "Failed", "error_message": str(exc)})
                self._job_manager.update(job_id, tool_results=tool_results)
            normalized = deduplicate_findings(normalized)
            normalized_path = output_dir / "normalized.json"
            write_json(normalized_path, [finding.model_dump(mode="json") for finding in normalized])
            self._job_manager.update(job_id, status=ScanJobStatus.AI_ANALYSIS, progress=75, current_scanner=None, current_phase="Generating AI Analysis", finding_count=len(normalized), normalized_output_path=str(normalized_path))
            history_context = project_service.historical_context(request.project_id)
            analysis = await process_vulnerabilities(normalized, history_context) if history_context is not None else await process_vulnerabilities(normalized)
            completed_tools = {item.scanner.title() if item.scanner != "httpx" else "HTTPX" for item in tool_results if item.status == "Completed"}
            analysis = analysis.model_copy(update={"summary": analysis.summary.model_copy(update={"tools_detected": sorted(set(analysis.summary.tools_detected) | completed_tools)})})
            job = self.get_job(job_id)
            if request.project_id:
                historical_summary = project_service.record_completed_scan(
                    request.project_id,
                    job,
                    analysis,
                    scan_type=request.scan_type,
                    target=request.target,
                    normalized_path=str(normalized_path),
                )
                analysis = analysis.model_copy(
                    update={
                        "analysis_metadata": (analysis.analysis_metadata or ScanAnalysisMetadata()).model_copy(
                            update={"historical_summary": historical_summary}
                        )
                    }
                )
            ai_path = output_dir / "ai.json"
            write_json(ai_path, analysis.model_dump(mode="json"))
            report_service.store_scan(analysis)
            report_path: Path | None = None
            if request.generate_executive_report:
                self._job_manager.update(
                    job_id,
                    status=ScanJobStatus.GENERATING_REPORT,
                    progress=95,
                    current_phase="Generating Report",
                    finding_count=analysis.summary.unique_findings,
                    ai_output_path=str(ai_path),
                    analysis=analysis,
                )
                _, report_path = report_service.generate_scan_report(
                    output_dir,
                    ReportMetadata(
                        assessment_date=date.today().isoformat(),
                        assessment_scope=request.target,
                        assessment_type=f"{', '.join(scanner.name for scanner in scanners)} Vulnerability Assessment",
                    ),
                )
            completed = datetime.now(UTC)
            self._job_manager.update(
                job_id,
                status=ScanJobStatus.COMPLETED,
                progress=100,
                current_scanner=None,
                current_phase="Scan analysis complete",
                completed_time=completed,
                duration=(completed - started).total_seconds(),
                finding_count=analysis.summary.unique_findings,
                raw_output_path=str(output_dir),
                normalized_output_path=str(normalized_path),
                ai_output_path=str(ai_path),
                report_path=str(report_path) if report_path else None,
                tool_results=tool_results,
                analysis=analysis,
            )
            if request.project_id and report_path:
                project_service.attach_report(request.project_id, job_id, str(report_path))
        except asyncio.CancelledError:
            completed = datetime.now(UTC)
            self._job_manager.update(
                job_id,
                status=ScanJobStatus.CANCELLED,
                current_phase="Scanner execution cancelled",
                completed_time=completed,
                duration=(completed - started).total_seconds(),
            )
            raise
        except (RuntimeError, ValueError, PermissionError, OSError) as exc:
            completed = datetime.now(UTC)
            self._job_manager.update(
                job_id,
                status=ScanJobStatus.FAILED,
                progress=100,
                current_phase="Scanner execution failed",
                completed_time=completed,
                duration=(completed - started).total_seconds(),
                error_message=str(exc),
            )
        finally:
            self._tasks.pop(job_id, None)
            self._active_scanners.pop(job_id, None)

    def get_job(self, job_id: str) -> ScanJob | None:
        return self._job_manager.get(job_id)

    def list_jobs(self) -> list[ScanJob]:
        return self._job_manager.list()

    def subscribe(self, job_id: str) -> tuple[ScanJob, asyncio.Queue[ScanJob]] | None:
        return self._job_manager.subscribe(job_id)

    def unsubscribe(self, job_id: str, queue: asyncio.Queue[ScanJob]) -> None:
        self._job_manager.unsubscribe(job_id, queue)

    def set_report_path(self, job_id: str, report_path: str) -> ScanJob | None:
        return self._job_manager.update(job_id, report_path=report_path)

    async def cancel_job(self, job_id: str) -> ScanJob | None:
        job = self._job_manager.get(job_id)
        if job is None:
            return None
        if job.status in {ScanJobStatus.COMPLETED, ScanJobStatus.FAILED, ScanJobStatus.CANCELLED}:
            raise ValueError(f"Job '{job_id}' is already in terminal state {job.status.value}.")
        scanners = self._active_scanners.get(job_id, [])
        await asyncio.gather(*(scanner.cancel_scan(job_id) for scanner in scanners))
        task = self._tasks.get(job_id)
        if task is not None:
            task.cancel()
        return self._job_manager.cancel(job_id)

    def registered_scanners(self) -> list[str]:
        return sorted(self._scanners)


def create_default_scanner_manager() -> ScannerManager:
    manager = ScannerManager()
    for adapter in (
        SubfinderScannerAdapter(), AmassScannerAdapter(), DNSxScannerAdapter(), HTTPXScannerAdapter(), NaabuScannerAdapter(),
        NmapScannerAdapter(), KatanaScannerAdapter(), HakrawlerScannerAdapter(), ArjunScannerAdapter(), NucleiScannerAdapter(),
        SemgrepScannerAdapter(), SyftScannerAdapter(), TrivyScannerAdapter(), OsvScannerAdapter(), ApktoolScannerAdapter(), JadxScannerAdapter(), NessusScannerAdapter(), BurpScannerAdapter(), MobSFScannerAdapter(),
    ):
        manager.register(adapter)
    return manager


scanner_manager = create_default_scanner_manager()
