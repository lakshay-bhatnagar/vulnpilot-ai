import logging

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings
from backend.models.schemas import ScanAnalysisResponse
from backend.parsers.burp_parser import parse_burp_xml
from backend.parsers.nuclei_parser import parse_nuclei_json
from backend.services.ai_engine import process_vulnerabilities

settings = get_settings()
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.app_name,
    description="Backend API for ingesting scanner artifacts and enriching vulnerability findings.",
    version="1.0.0",
)

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
async def upload_scan(file: UploadFile = File(...)) -> ScanAnalysisResponse:
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
        if filename.endswith(".xml"):
            findings = parse_burp_xml(content)
        elif filename.endswith(".json"):
            findings = parse_nuclei_json(content)
        else:
            raise HTTPException(
                status_code=415,
                detail="Unsupported file type. Upload a Burp Suite .xml or Nuclei .json export.",
            )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Failed to parse upload: {exc}") from exc

    if not findings:
        raise HTTPException(status_code=422, detail="No vulnerabilities were found in the uploaded file.")

    try:
        analysis = await process_vulnerabilities(findings)
        logger.info("[Scan upload] Returning response: %s", analysis.model_dump(mode="json"))
        return analysis
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
