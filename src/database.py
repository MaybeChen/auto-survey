"""SQLite persistence for capture recovery and cross-file endpoint aggregation."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from importlib.resources import files
from pathlib import Path
from typing import Any

from src.endpoint.cluster import EndpointGroup
from src.models import CaptureStatus, EndpointAnalysisResult, Transaction


class Database:
    """Small transactional repository; each public mutation commits atomically."""

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        schema = files("src.sql").joinpath("schema.sql").read_text(encoding="utf-8")
        self.connection.executescript(schema)

    @staticmethod
    def sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def register_capture(self, path: Path, force: bool = False) -> tuple[int, bool]:
        digest = self.sha256(path)
        row = self.connection.execute(
            "SELECT id,status FROM capture_file WHERE sha256=?", (digest,)
        ).fetchone()
        if row and not force:
            return int(row["id"]), False
        if row:
            self.connection.execute(
                "UPDATE capture_file SET path=?,status=?,error=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (str(path), CaptureStatus.DISCOVERED, int(row["id"])),
            )
            self.connection.commit()
            return int(row["id"]), True
        cursor = self.connection.execute(
            "INSERT INTO capture_file(path,sha256,status) VALUES(?,?,?)",
            (str(path), digest, CaptureStatus.DISCOVERED),
        )
        self.connection.commit()
        return int(cursor.lastrowid), True

    def set_capture_status(
        self,
        capture_id: int,
        status: CaptureStatus,
        error: str | None = None,
        stats: dict[str, int] | None = None,
    ) -> None:
        self.connection.execute(
            "UPDATE capture_file SET status=?,error=?,protocol_stats=COALESCE(?,protocol_stats),updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (status, error, json.dumps(stats) if stats is not None else None, capture_id),
        )
        self.connection.commit()

    def start_run(self, capture_id: int) -> int:
        cursor = self.connection.execute(
            "INSERT INTO analysis_run(capture_file_id,status) VALUES(?,?)",
            (capture_id, "RUNNING"),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def finish_run(self, run_id: int, status: str, error: str | None = None) -> None:
        self.connection.execute(
            "UPDATE analysis_run SET status=?,error=?,finished_at=CURRENT_TIMESTAMP WHERE id=?",
            (status, error, run_id),
        )
        self.connection.commit()

    def save_transaction(self, capture_id: int, transaction: Transaction) -> None:
        """Persist only the redacted transaction used by downstream analysis."""
        self.connection.execute(
            'INSERT INTO "transaction"(id,capture_file_id,payload) VALUES(?,?,?) '
            'ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,capture_file_id=excluded.capture_file_id',
            (transaction.id, capture_id, transaction.model_dump_json()),
        )
        self.connection.commit()

    def upsert_endpoint(self, group: EndpointGroup) -> int:
        self.connection.execute(
            """INSERT INTO endpoint(host,method,normalized_path,status)
               VALUES(?,?,?,'DISCOVERED')
               ON CONFLICT(host,method,normalized_path)
               DO UPDATE SET updated_at=CURRENT_TIMESTAMP""",
            group.key,
        )
        row = self.connection.execute(
            "SELECT id FROM endpoint WHERE host=? AND method=? AND normalized_path=?",
            group.key,
        ).fetchone()
        assert row is not None
        return int(row["id"])

    def add_endpoint_sample(self, endpoint_id: int, transaction_id: str) -> None:
        self.connection.execute(
            "INSERT OR IGNORE INTO endpoint_sample(endpoint_id,transaction_id) VALUES(?,?)",
            (endpoint_id, transaction_id),
        )
        self.connection.execute(
            """UPDATE endpoint SET sample_count=(
                   SELECT COUNT(*) FROM endpoint_sample WHERE endpoint_id=?
               ),updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (endpoint_id, endpoint_id),
        )
        self.connection.commit()

    def load_endpoint_groups(self, max_samples: int) -> list[tuple[int, EndpointGroup]]:
        endpoints = self.connection.execute(
            "SELECT id,host,method,normalized_path FROM endpoint ORDER BY host,method,normalized_path"
        ).fetchall()
        result: list[tuple[int, EndpointGroup]] = []
        for endpoint in endpoints:
            rows = self.connection.execute(
                """SELECT t.payload FROM endpoint_sample es
                   JOIN "transaction" t ON t.id=es.transaction_id
                   WHERE es.endpoint_id=? ORDER BY es.id DESC LIMIT ?""",
                (int(endpoint["id"]), max_samples),
            ).fetchall()
            samples = [Transaction.model_validate_json(row["payload"]) for row in reversed(rows)]
            result.append(
                (
                    int(endpoint["id"]),
                    EndpointGroup(
                        host=endpoint["host"],
                        method=endpoint["method"],
                        normalized_path=endpoint["normalized_path"],
                        samples=samples,
                    ),
                )
            )
        return result

    def update_endpoint(self, endpoint_id: int, status: str, confidence: float) -> None:
        self.connection.execute(
            "UPDATE endpoint SET status=?,confidence=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (status, confidence, endpoint_id),
        )
        self.connection.commit()

    def save_observations(
        self, endpoint_id: int, location: str, observations: dict[str, Any]
    ) -> None:
        for field_path, observation in observations.items():
            self.connection.execute(
                """INSERT INTO field_observation(endpoint_id,location,field_path,observation)
                   VALUES(?,?,?,?) ON CONFLICT(endpoint_id,location,field_path)
                   DO UPDATE SET observation=excluded.observation,updated_at=CURRENT_TIMESTAMP""",
                (endpoint_id, location, field_path, json.dumps(observation, ensure_ascii=False)),
            )
        self.connection.commit()

    def save_ai_analysis(
        self,
        endpoint_id: int,
        result: EndpointAnalysisResult | None,
        error: str | None = None,
    ) -> None:
        self.connection.execute(
            "INSERT INTO ai_analysis(endpoint_id,status,result,error) VALUES(?,?,?,?)",
            (
                endpoint_id,
                "DONE" if result is not None else "FAILED_AI_PARSE",
                result.model_dump_json() if result is not None else None,
                error,
            ),
        )
        self.connection.commit()

    def statuses(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT status,COUNT(*) count FROM capture_file GROUP BY status"
            )
        ]

    def status_report(self) -> dict[str, Any]:
        """Return capture, endpoint, and analysis-run counts for operators."""
        return {
            "captureFiles": self.statuses(),
            "endpoints": [
                dict(row)
                for row in self.connection.execute(
                    "SELECT status,COUNT(*) count FROM endpoint GROUP BY status"
                )
            ],
            "analysisRuns": [
                dict(row)
                for row in self.connection.execute(
                    "SELECT status,COUNT(*) count FROM analysis_run GROUP BY status"
                )
            ],
        }

    def recover_interrupted(self) -> int:
        cursor = self.connection.execute(
            """UPDATE capture_file SET status='STABLE',error='recovered after interrupted run',
               updated_at=CURRENT_TIMESTAMP
               WHERE status IN ('PROBING','PARSING','ANALYZING')"""
        )
        self.connection.execute(
            """UPDATE analysis_run SET status='FAILED',error='recovered after interrupted run',
               finished_at=CURRENT_TIMESTAMP WHERE status='RUNNING'"""
        )
        self.connection.commit()
        return cursor.rowcount
