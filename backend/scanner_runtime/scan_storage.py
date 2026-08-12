"""Safe per-job raw-output storage for the scanner runtime."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID


class ScanStorage:
    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or Path("storage/scans")).resolve()

    def job_directory(self, job_id: str) -> Path:
        try:
            safe_job_id = str(UUID(job_id))
        except ValueError as exc:
            raise ValueError("Scanner job ID must be a UUID.") from exc
        directory = (self.root / safe_job_id).resolve()
        if self.root not in directory.parents:
            raise ValueError("Invalid scanner job storage path.")
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def write_metadata(self, job_id: str, metadata: dict[str, object]) -> Path:
        path = self.job_directory(job_id) / "runtime-job.json"
        path.write_text(json.dumps(metadata, indent=2, default=str), encoding="utf-8")
        return path
