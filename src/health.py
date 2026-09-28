"""Operational preflight checks shared by CLI and service health probes."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from src.config import AppConfig
from src.database import Database
from src.output.atomic import atomic_write_text
from src.platform import PlatformAdapter, get_platform_adapter
from src.platform.interfaces import list_dumpcap_interfaces


def run_checks(
    config: AppConfig, adapter: PlatformAdapter | None = None
) -> dict[str, Any]:
    """Check tools, writable storage, capture permissions, and optional SQLite."""
    platform_adapter = adapter or get_platform_adapter()
    checks: list[dict[str, Any]] = []

    def check(name: str, action: Any) -> None:
        try:
            detail = action()
            checks.append({"name": name, "ok": True, "detail": str(detail)})
        except Exception as exc:
            checks.append({"name": name, "ok": False, "detail": str(exc)})

    paths = config.create_directories()
    check("tshark", lambda: config.tshark.path or platform_adapter.find_tshark())
    check("dumpcap", lambda: config.dumpcap.path or platform_adapter.find_dumpcap())
    def capture_check() -> str:
        if config.dumpcap.path:
            interfaces = list_dumpcap_interfaces(config.dumpcap.path)
            return f"available ({len(interfaces)} interfaces)"
        if not platform_adapter.validate_capture_permissions():
            raise RuntimeError("capture permission check failed")
        return "available"

    check("capture-permissions", capture_check)

    def storage_check() -> Path:
        probe = paths["state"] / ".healthcheck"
        atomic_write_text(probe, "ok\n")
        probe.unlink()
        return config.storage.root

    check("storage-write", storage_check)
    if config.database.enabled:
        database_path = (
            Path(config.database.url)
            if config.database.url
            else paths["state"] / "agent.db"
        )
        check("database", lambda: Database(database_path).path)
    else:
        checks.append({"name": "database", "ok": True, "detail": "disabled"})
    return {"healthy": all(item["ok"] for item in checks), "checks": checks}
