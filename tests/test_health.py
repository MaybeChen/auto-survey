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
