"""Project endpoints; scan execution remains delegated to ScannerManager."""

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.jobs.models import CreateScanJobRequest, ScanJob
from backend.scanners.scanner_manager import scanner_manager
from backend.services.project_service import project_service

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])


class CreateProjectRequest(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=2000)


class CreateAssetRequest(BaseModel):
    asset_type: str
    value: str = Field(min_length=1, max_length=2048)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_project(request: CreateProjectRequest) -> dict[str, Any]:
    try:
        return project_service.create_project(request.name, request.description)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("")
async def list_projects() -> list[dict[str, Any]]:
    return project_service.list_projects()


@router.get("/{project_id}")
async def get_project(project_id: str) -> dict[str, Any]:
    try:
        return project_service.get_project(project_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{project_id}/assets", status_code=status.HTTP_201_CREATED)
async def add_project_asset(project_id: str, request: CreateAssetRequest) -> dict[str, str]:
    try:
        return project_service.add_asset(project_id, request.asset_type, request.value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/{project_id}/scans", response_model=ScanJob, status_code=status.HTTP_202_ACCEPTED)
async def create_project_scan(project_id: str, request: CreateScanJobRequest) -> ScanJob:
    try:
        project_service.get_project(project_id)
        return await scanner_manager.launch_job(request.model_copy(update={"project_id": project_id}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/{project_id}/scans/{session_id}/compare")
async def compare_project_scans(project_id: str, session_id: str, baseline_session_id: str | None = None) -> dict[str, Any]:
    try:
        return project_service.compare_sessions(project_id, session_id, baseline_session_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
