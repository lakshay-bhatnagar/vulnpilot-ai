"""Scan orchestration endpoints backed solely by ScannerManager."""

import asyncio
import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import StreamingResponse

from backend.jobs.models import CreateScanJobRequest, ScanJob
from backend.models.schemas import ScanAnalysisResponse
from backend.config import get_settings
from backend.scanners.scanner_manager import scanner_manager

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


@router.post("", response_model=ScanJob, status_code=status.HTTP_202_ACCEPTED)
async def create_scan_job(request: CreateScanJobRequest) -> ScanJob:
    try:
        return await scanner_manager.launch_job(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/source-code", response_model=ScanJob, status_code=status.HTTP_202_ACCEPTED)
async def create_source_code_scan(
    file: UploadFile | None = File(default=None),
    repository_url: str | None = Form(default=None),
    local_path: str | None = Form(default=None),
    profile_mode: str = Form(default="standard"),
    generate_executive_report: bool = Form(default=False),
    project_id: str | None = Form(default=None),
) -> ScanJob:
    supplied_sources = sum(value is not None and value != "" for value in (file, repository_url, local_path))
    if supplied_sources != 1:
        raise HTTPException(status_code=422, detail="Provide exactly one source archive, Git repository URL, or local source directory.")
    archive_content: bytes | None = None
    archive_name: str | None = None
    if file is not None:
        archive_name = file.filename
        if not archive_name:
            raise HTTPException(status_code=422, detail="Source archive must have a filename.")
        if not archive_name.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
            raise HTTPException(status_code=415, detail="Source archives must be ZIP or TAR variants.")
        archive_content = await file.read()
        max_bytes = get_settings().max_upload_size_mb * 1024 * 1024
        if not archive_content or len(archive_content) > max_bytes:
            raise HTTPException(status_code=413, detail=f"Source archive must be between 1 byte and {get_settings().max_upload_size_mb} MB.")
    target = repository_url or local_path or archive_name or "source-upload"
    request = CreateScanJobRequest(
        scanner="semgrep",
        target=target,
        scan_profile="source_code_assessment",
        profile_mode=profile_mode,
        generate_executive_report=generate_executive_report,
        project_id=project_id,
    )
    try:
        return await scanner_manager.launch_source_code_job(
            request,
            archive_name=archive_name,
            archive_content=archive_content,
            repository_url=repository_url,
            local_path=local_path,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/dependency", response_model=ScanJob, status_code=status.HTTP_202_ACCEPTED)
async def create_dependency_scan(
    file: UploadFile | None = File(default=None),
    repository_url: str | None = Form(default=None),
    local_path: str | None = Form(default=None),
    profile_mode: str = Form(default="standard"),
    generate_executive_report: bool = Form(default=False),
    project_id: str | None = Form(default=None),
) -> ScanJob:
    supplied_sources = sum(value is not None and value != "" for value in (file, repository_url, local_path))
    if supplied_sources != 1:
        raise HTTPException(status_code=422, detail="Provide exactly one project archive, Git repository URL, or local project directory.")
    archive_content: bytes | None = None
    archive_name: str | None = None
    if file is not None:
        archive_name = file.filename
        if not archive_name or not archive_name.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
            raise HTTPException(status_code=415, detail="Project archives must be ZIP or TAR variants.")
        archive_content = await file.read()
        max_bytes = get_settings().max_upload_size_mb * 1024 * 1024
        if not archive_content or len(archive_content) > max_bytes:
            raise HTTPException(status_code=413, detail=f"Project archive must be between 1 byte and {get_settings().max_upload_size_mb} MB.")
    target = repository_url or local_path or archive_name or "project-upload"
    request = CreateScanJobRequest(scanner="syft", target=target, scan_profile="software_composition_analysis", profile_mode=profile_mode, generate_executive_report=generate_executive_report, project_id=project_id)
    try:
        return await scanner_manager.launch_dependency_scan_job(request, archive_name=archive_name, archive_content=archive_content, repository_url=repository_url, local_path=local_path)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/mobile", response_model=ScanJob, status_code=status.HTTP_202_ACCEPTED)
async def create_mobile_scan(
    file: UploadFile = File(...),
    profile_mode: str = Form(default="standard"),
    generate_executive_report: bool = Form(default=False),
    project_id: str | None = Form(default=None),
) -> ScanJob:
    if not file.filename:
        raise HTTPException(status_code=422, detail="Mobile package must have a filename.")
    content = await file.read()
    max_bytes = get_settings().max_upload_size_mb * 1024 * 1024
    if not content or len(content) > max_bytes:
        raise HTTPException(status_code=413, detail=f"Mobile package must be between 1 byte and {get_settings().max_upload_size_mb} MB.")
    request = CreateScanJobRequest(scanner="mobsf", target=file.filename, scan_profile="mobile_assessment", profile_mode=profile_mode, generate_executive_report=generate_executive_report, project_id=project_id)
    try:
        return await scanner_manager.launch_mobile_job(request, filename=file.filename, content=content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("", response_model=list[ScanJob])
async def list_scan_jobs() -> list[ScanJob]:
    return scanner_manager.list_jobs()


def _sse_event(job: ScanJob) -> str:
    """Serialize one complete job snapshot as an SSE named event."""
    payload = json.dumps(job.model_dump(mode="json"), separators=(",", ":"))
    return f"event: scan-update\ndata: {payload}\n\n"


@router.get("/{job_id}/events")
async def stream_scan_job_events(job_id: str, request: Request) -> StreamingResponse:
    """Stream per-job state snapshots to independently connected clients."""
    subscription = scanner_manager.subscribe(job_id)
    if subscription is None:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' was not found.")
    initial_job, queue = subscription

    async def event_stream() -> AsyncIterator[str]:
        try:
            # The initial state closes the race between job creation and a client
            # opening its stream, and also gives reconnecting clients a resync.
            yield _sse_event(initial_job)
            while not await request.is_disconnected():
                try:
                    job = await asyncio.wait_for(queue.get(), timeout=15)
                    yield _sse_event(job)
                except TimeoutError:
                    # Keeps proxies and browser connections alive when a scanner
                    # has no granular progress callback of its own.
                    yield ": keep-alive\n\n"
        finally:
            scanner_manager.unsubscribe(job_id, queue)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{job_id}/analysis", response_model=ScanAnalysisResponse)
async def get_scan_analysis(job_id: str) -> ScanAnalysisResponse:
    job = scanner_manager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' was not found.")
    if job.analysis is None:
        raise HTTPException(status_code=409, detail=f"Scan job '{job_id}' has not completed AI analysis yet.")
    return job.analysis


@router.get("/{job_id}", response_model=ScanJob)
async def get_scan_job(job_id: str) -> ScanJob:
    job = scanner_manager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' was not found.")
    return job


@router.delete("/{job_id}", response_model=ScanJob)
async def cancel_scan_job(job_id: str) -> ScanJob:
    try:
        job = await scanner_manager.cancel_job(job_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' was not found.")
    return job
