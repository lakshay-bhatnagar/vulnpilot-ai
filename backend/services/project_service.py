"""Persistent project, asset, and scan-history storage.

This module deliberately uses SQLite from the standard library so project state is
durable without introducing a second persistence runtime beside FastAPI.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from backend.jobs.models import ScanJob
from backend.models.schemas import HistoricalFindingSummary, ScanAnalysisResponse, Severity, VulnerabilityItem


SEVERITY_WEIGHTS = {Severity.CRITICAL.value: 10, Severity.HIGH.value: 6, Severity.MEDIUM.value: 3, Severity.LOW.value: 1}
ASSET_TYPES = {"domain", "ip", "cidr", "repository", "apk", "ipa"}


class ProjectService:
    def __init__(self, database_path: Path | None = None) -> None:
        self._database_path = database_path or Path("storage/vulnpilot.db")
        self._lock = RLock()
        self._initialize()

    def _connection(self) -> sqlite3.Connection:
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self._database_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connection() as connection:
            connection.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS project_assets (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    asset_type TEXT NOT NULL, value TEXT NOT NULL, created_at TEXT NOT NULL,
                    UNIQUE(project_id, asset_type, value)
                );
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    scan_job_id TEXT, scan_type TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL,
                    created_at TEXT NOT NULL, completed_at TEXT, risk_score INTEGER NOT NULL DEFAULT 0,
                    analysis_json TEXT NOT NULL, normalized_path TEXT, ai_path TEXT, report_path TEXT
                );
                CREATE TABLE IF NOT EXISTS finding_snapshots (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    session_id TEXT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
                    fingerprint TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, target TEXT NOT NULL,
                    state TEXT NOT NULL, classification TEXT NOT NULL, payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_project_sessions ON scan_sessions(project_id, completed_at DESC);
                CREATE INDEX IF NOT EXISTS idx_project_findings ON finding_snapshots(project_id, session_id, fingerprint);
                """
            )

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    @staticmethod
    def _fingerprint(finding: VulnerabilityItem) -> str:
        root = "|".join(
            value.strip().lower()
            for value in (finding.target_url, finding.cwe or finding.cve or finding.title, finding.package_name or "")
        )
        return hashlib.sha256(root.encode("utf-8")).hexdigest()

    @staticmethod
    def _risk_score(findings: list[VulnerabilityItem]) -> int:
        return min(100, sum(SEVERITY_WEIGHTS[item.severity.value] for item in findings))

    def _require_project(self, connection: sqlite3.Connection, project_id: str) -> sqlite3.Row:
        project = connection.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if project is None:
            raise ValueError(f"Project '{project_id}' was not found.")
        return project

    def create_project(self, name: str, description: str = "") -> dict[str, Any]:
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Project name is required.")
        project_id, now = str(uuid4()), self._now()
        with self._lock, self._connection() as connection:
            connection.execute("INSERT INTO projects (id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", (project_id, clean_name, description.strip(), now, now))
        return self.get_project(project_id)

    def add_asset(self, project_id: str, asset_type: str, value: str) -> dict[str, str]:
        kind, clean_value = asset_type.strip().lower(), value.strip()
        if kind not in ASSET_TYPES:
            raise ValueError(f"Unsupported asset type '{asset_type}'.")
        if not clean_value:
            raise ValueError("Asset value is required.")
        asset = {"id": str(uuid4()), "project_id": project_id, "asset_type": kind, "value": clean_value, "created_at": self._now()}
        with self._lock, self._connection() as connection:
            self._require_project(connection, project_id)
            try:
                connection.execute("INSERT INTO project_assets (id, project_id, asset_type, value, created_at) VALUES (:id, :project_id, :asset_type, :value, :created_at)", asset)
            except sqlite3.IntegrityError as exc:
                raise ValueError("This asset is already associated with the project.") from exc
            connection.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (self._now(), project_id))
        return asset

    def list_projects(self) -> list[dict[str, Any]]:
        with self._lock, self._connection() as connection:
            rows = connection.execute("SELECT id FROM projects ORDER BY updated_at DESC").fetchall()
        return [self.get_project(row["id"]) for row in rows]

    def get_project(self, project_id: str) -> dict[str, Any]:
        with self._lock, self._connection() as connection:
            project = self._require_project(connection, project_id)
            assets = [dict(row) for row in connection.execute("SELECT id, asset_type, value, created_at FROM project_assets WHERE project_id = ? ORDER BY created_at", (project_id,))]
            sessions = connection.execute("SELECT * FROM scan_sessions WHERE project_id = ? ORDER BY completed_at DESC, created_at DESC", (project_id,)).fetchall()
            latest = sessions[0] if sessions else None
            previous = sessions[1] if len(sessions) > 1 else None
            risk_score = int(latest["risk_score"]) if latest else 0
            trend = "new" if latest and not previous else ("stable" if not latest or risk_score == int(previous["risk_score"]) else "increasing" if risk_score > int(previous["risk_score"]) else "decreasing")
            states = connection.execute("SELECT state, COUNT(*) AS count FROM finding_snapshots WHERE session_id = ? GROUP BY state", (latest["id"],)).fetchall() if latest else []
        counts = {row["state"]: row["count"] for row in states}
        return {
            "id": project["id"], "name": project["name"], "description": project["description"], "created_at": project["created_at"], "updated_at": project["updated_at"],
            "assets": assets, "scan_history": [self._session_dict(row) for row in sessions], "risk_score": risk_score, "trend": trend,
            "open_findings": counts.get("open", 0), "resolved_findings": counts.get("resolved", 0),
        }

    @staticmethod
    def _session_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {key: row[key] for key in ("id", "scan_job_id", "scan_type", "target", "status", "created_at", "completed_at", "risk_score", "normalized_path", "ai_path", "report_path")}

    def historical_context(self, project_id: str | None) -> dict[str, Any] | None:
        if not project_id:
            return None
        with self._lock, self._connection() as connection:
            self._require_project(connection, project_id)
            latest = connection.execute("SELECT id, risk_score FROM scan_sessions WHERE project_id = ? AND status = 'Completed' ORDER BY completed_at DESC LIMIT 1", (project_id,)).fetchone()
            if latest is None:
                return {"previous_findings": [], "previous_risk_score": 0}
            findings = connection.execute("SELECT fingerprint, title, severity, target FROM finding_snapshots WHERE session_id = ? AND state = 'open'", (latest["id"],)).fetchall()
        return {"previous_risk_score": latest["risk_score"], "previous_findings": [dict(row) for row in findings]}

    def record_completed_scan(self, project_id: str, job: ScanJob | None, analysis: ScanAnalysisResponse, *, scan_type: str, target: str, normalized_path: str | None = None, ai_path: str | None = None) -> HistoricalFindingSummary:
        session_id, now = (job.job_id if job else str(uuid4())), self._now()
        findings = analysis.findings
        current = {self._fingerprint(item): item for item in findings}
        risk_score = self._risk_score(findings)
        with self._lock, self._connection() as connection:
            self._require_project(connection, project_id)
            prior = connection.execute("SELECT id, risk_score FROM scan_sessions WHERE project_id = ? AND status = 'Completed' ORDER BY completed_at DESC LIMIT 1", (project_id,)).fetchone()
            prior_open: dict[str, sqlite3.Row] = {}
            if prior:
                prior_open = {row["fingerprint"]: row for row in connection.execute("SELECT * FROM finding_snapshots WHERE session_id = ? AND state = 'open'", (prior["id"],))}
            new_keys, recurring_keys, resolved_keys = set(current) - set(prior_open), set(current) & set(prior_open), set(prior_open) - set(current)
            trend = "new" if prior is None else "stable" if risk_score == prior["risk_score"] else "increasing" if risk_score > prior["risk_score"] else "decreasing"
            connection.execute("INSERT OR REPLACE INTO scan_sessions (id, project_id, scan_job_id, scan_type, target, status, created_at, completed_at, risk_score, analysis_json, normalized_path, ai_path) VALUES (?, ?, ?, ?, ?, 'Completed', ?, ?, ?, ?, ?, ?)", (session_id, project_id, job.job_id if job else None, scan_type, target, now, now, risk_score, analysis.model_dump_json(), normalized_path, ai_path))
            for fingerprint, finding in current.items():
                classification = "recurring" if fingerprint in recurring_keys else "new"
                connection.execute("INSERT INTO finding_snapshots (id, project_id, session_id, fingerprint, title, severity, target, state, classification, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)", (str(uuid4()), project_id, session_id, fingerprint, finding.title, finding.severity.value, finding.target_url, classification, finding.model_dump_json()))
            for fingerprint in resolved_keys:
                old = prior_open[fingerprint]
                connection.execute("INSERT INTO finding_snapshots (id, project_id, session_id, fingerprint, title, severity, target, state, classification, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, 'resolved', 'resolved', ?)", (str(uuid4()), project_id, session_id, fingerprint, old["title"], old["severity"], old["target"], old["payload_json"]))
            connection.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
        return HistoricalFindingSummary(new_findings=len(new_keys), resolved_findings=len(resolved_keys), recurring_findings=len(recurring_keys), risk_trend=trend)

    def attach_report(self, project_id: str, session_id: str, report_path: str) -> None:
        with self._lock, self._connection() as connection:
            self._require_project(connection, project_id)
            connection.execute("UPDATE scan_sessions SET report_path = ? WHERE id = ? AND project_id = ?", (report_path, session_id, project_id))
            connection.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (self._now(), project_id))

    def get_session(self, project_id: str, session_id: str | None = None) -> dict[str, Any]:
        with self._lock, self._connection() as connection:
            self._require_project(connection, project_id)
            query = "SELECT * FROM scan_sessions WHERE project_id = ?" + (" AND id = ?" if session_id else "") + " ORDER BY completed_at DESC LIMIT 1"
            row = connection.execute(query, (project_id, session_id) if session_id else (project_id,)).fetchone()
            if row is None:
                raise ValueError("No completed scan session is available for this project.")
        return self._session_dict(row)

    def compare_sessions(self, project_id: str, current_session_id: str, baseline_session_id: str | None = None) -> dict[str, Any]:
        with self._lock, self._connection() as connection:
            self._require_project(connection, project_id)
            current = connection.execute("SELECT * FROM scan_sessions WHERE id = ? AND project_id = ?", (current_session_id, project_id)).fetchone()
            if current is None:
                raise ValueError("Current scan session was not found.")
            baseline = connection.execute("SELECT * FROM scan_sessions WHERE project_id = ? AND id != ? ORDER BY completed_at DESC LIMIT 1", (project_id, current_session_id)).fetchone() if baseline_session_id is None else connection.execute("SELECT * FROM scan_sessions WHERE id = ? AND project_id = ?", (baseline_session_id, project_id)).fetchone()
            current_rows = {row["fingerprint"]: dict(row) for row in connection.execute("SELECT * FROM finding_snapshots WHERE session_id = ? AND state = 'open'", (current_session_id,))}
            old_rows = {} if baseline is None else {row["fingerprint"]: dict(row) for row in connection.execute("SELECT * FROM finding_snapshots WHERE session_id = ? AND state = 'open'", (baseline["id"],))}
        return {"current_session_id": current_session_id, "baseline_session_id": baseline["id"] if baseline else None, "new_findings": [current_rows[key] for key in current_rows.keys() - old_rows.keys()], "recurring_findings": [current_rows[key] for key in current_rows.keys() & old_rows.keys()], "resolved_findings": [old_rows[key] for key in old_rows.keys() - current_rows.keys()], "risk_trend": "new" if baseline is None else "stable" if current["risk_score"] == baseline["risk_score"] else "increasing" if current["risk_score"] > baseline["risk_score"] else "decreasing"}


project_service = ProjectService()
