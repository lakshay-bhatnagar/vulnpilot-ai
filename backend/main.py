import logging
from time import perf_counter

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings
from backend.models.schemas import ScanAnalysisMetadata, ScanAnalysisResponse
from backend.parsers.factory import get_parser
from backend.routes.report import router as report_router
from backend.routes.scans import router as scans_router
from backend.routes.projects import router as projects_router
from backend.services.ai_engine import process_vulnerabilities
from backend.services.project_service import project_service
from backend.services.report_service import report_service

settings = get_settings()
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.app_name,
    description="Backend API for ingesting scanner artifacts and enriching vulnerability findings.",
    version="1.0.0",
)
app.include_router(report_router)
app.include_router(scans_router)
app.include_router(projects_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://localhost:8080",
        "htcletp://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get(f"{settings.api_prefix}/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


@app.post(f"{settings.api_prefix}/scan/upload", response_model=ScanAnalysisResponse)
async def upload_scan(file: UploadFile = File(...), project_id: str | None = Form(default=None)) -> ScanAnalysisResponse:
    processing_started = perf_counter()
    if not file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file must have a filename.")

    filename = file.filename.lower()
    content = await file.read()

    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum upload size of {settings.max_upload_size_mb} MB.",
        )

    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        findings = get_parser(filename, content)(content)
    except ValueError as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Failed to parse upload: {exc}") from exc

    if not findings:
        raise HTTPException(status_code=422, detail="No vulnerabilities were found in the uploaded file.")

    try:
        analysis = await process_vulnerabilities(findings, project_service.historical_context(project_id))
        existing_metadata = analysis.analysis_metadata or ScanAnalysisMetadata()
        analysis = analysis.model_copy(
            update={
                "analysis_metadata": existing_metadata.model_copy(
                    update={
                        "detected_scanner": ", ".join(sorted({finding.tool_source for finding in findings})),
                        "processing_duration_ms": round((perf_counter() - processing_started) * 1000),
                    }
                )
            }
        )
        if project_id:
            history = project_service.record_completed_scan(
                project_id, None, analysis, scan_type="uploaded-artifact", target=file.filename,
            )
            analysis = analysis.model_copy(update={"analysis_metadata": analysis.analysis_metadata.model_copy(update={"historical_summary": history})})
        report_service.store_scan(analysis)
        logger.info("[Scan upload] Returning response: %s", analysis.model_dump(mode="json"))
        return analysis
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
