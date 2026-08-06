"""Executive report HTTP endpoints."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Response

from backend.models.schemas import ReportGenerateRequest
from backend.scanners.scanner_manager import scanner_manager
from backend.services.report_service import report_service
from backend.services.project_service import project_service

router = APIRouter(prefix="/api/v1/report", tags=["reports"])


def _pdf_response(pdf: bytes, disposition: str) -> Response:
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'{disposition}; filename="vulnpilot-executive-report.pdf"'},
    )


def _scan_directory(job_id: str) -> Path:
    job = scanner_manager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' was not found.")
    if not job.raw_output_path:
        raise HTTPException(status_code=409, detail="This scan has not stored any results yet.")
    return Path(job.raw_output_path)


def _project_scan_directory(project_id: str, session_id: str | None) -> tuple[Path, str]:
    session = project_service.get_session(project_id, session_id)
    if not session["normalized_path"]:
        raise HTTPException(status_code=409, detail="This project scan has not stored normalized findings yet.")
    return Path(session["normalized_path"]).parent, session["id"]


@router.post("/regenerate")
async def regenerate_report(request: ReportGenerateRequest, job_id: str | None = Query(default=None), project_id: str | None = Query(default=None), session_id: str | None = Query(default=None)) -> Response:
    try:
        if job_id:
            scan_directory = _scan_directory(job_id)
            pdf, report_path = report_service.generate_scan_report(scan_directory, request.metadata)
            scanner_manager.set_report_path(job_id, str(report_path))
            return _pdf_response(pdf, "inline")
        if project_id:
            scan_directory, resolved_session_id = _project_scan_directory(project_id, session_id)
            pdf, report_path = report_service.generate_scan_report(scan_directory, request.metadata)
            project_service.attach_report(project_id, resolved_session_id, str(report_path))
            return _pdf_response(pdf, "inline")
        return _pdf_response(report_service.generate(request.metadata), "inline")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/preview")
async def preview_report(job_id: str | None = Query(default=None), project_id: str | None = Query(default=None), session_id: str | None = Query(default=None)) -> Response:
    try:
        if job_id:
            return _pdf_response(report_service.scan_pdf(_scan_directory(job_id)), "inline")
        if project_id:
            scan_directory, _ = _project_scan_directory(project_id, session_id)
            return _pdf_response(report_service.scan_pdf(scan_directory), "inline")
        return _pdf_response(report_service.latest_pdf(), "inline")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/download")
async def download_report(job_id: str | None = Query(default=None), project_id: str | None = Query(default=None), session_id: str | None = Query(default=None)) -> Response:
    try:
        if job_id:
            return _pdf_response(report_service.scan_pdf(_scan_directory(job_id)), "attachment")
        if project_id:
            scan_directory, _ = _project_scan_directory(project_id, session_id)
            return _pdf_response(report_service.scan_pdf(scan_directory), "attachment")
        return _pdf_response(report_service.latest_pdf(), "attachment")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
