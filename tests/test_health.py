from pathlib import Path

from src.config import AppConfig, StorageConfig
from src.health import run_checks
from src.platform.base import PlatformAdapter


class HealthyAdapter(PlatformAdapter):
    def find_tshark(self) -> Path:
        return Path("tshark")

    def find_dumpcap(self) -> Path:
        return Path("dumpcap")

    def list_interfaces(self) -> list[dict[str, str]]:
        return [{"index": "1", "name": "test"}]

    def validate_capture_permissions(self) -> bool:
        return True


def test_doctor_checks_storage_tools_permissions_and_database(tmp_path):
    config = AppConfig(storage=StorageConfig(root=tmp_path))
    result = run_checks(config, HealthyAdapter())
    assert result["healthy"] is True
    assert {check["name"] for check in result["checks"]} == {
        "tshark",
        "dumpcap",
        "capture-permissions",
        "storage-write",
        "database",
    }
    assert (tmp_path / "state" / "agent.db").is_file()


def test_doctor_uses_explicit_dumpcap_path(tmp_path, monkeypatch):
    config = AppConfig(storage=StorageConfig(root=tmp_path))
    config.dumpcap.path = Path("D:/Wireshark/dumpcap.exe")
    monkeypatch.setattr(
        "src.health.list_dumpcap_interfaces",
        lambda executable: [{"index": "1", "name": str(executable)}],
    )
    result = run_checks(config, HealthyAdapter())
    permission = next(
        check for check in result["checks"] if check["name"] == "capture-permissions"
    )
    assert permission == {
        "name": "capture-permissions",
        "ok": True,
        "detail": "available (1 interfaces)",
    }
