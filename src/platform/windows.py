"""Windows tool discovery and capture capability checks."""
from pathlib import Path
import shutil
import subprocess

from .base import PlatformAdapter


class NpcapUnavailableError(RuntimeError):
    """Raised when dumpcap exists but the Npcap runtime is unavailable."""


class WindowsPlatformAdapter(PlatformAdapter):
    def _find(self, name: str) -> Path:
        found = shutil.which(name) or shutil.which(f"{name}.exe")
        candidate = Path("C:/Program Files/Wireshark") / f"{name}.exe"
        if found:
            return Path(found)
        if candidate.exists():
            return candidate
        raise FileNotFoundError(
            f"{name}.exe not found; install Wireshark and Npcap or add it to PATH"
        )

    def find_tshark(self) -> Path:
        return self._find("tshark")

    def find_dumpcap(self) -> Path:
        return self._find("dumpcap")

    def list_interfaces(self) -> list[dict[str, str]]:
        return _interfaces(self.find_dumpcap())

    def validate_capture_permissions(self) -> bool:
        try:
            _interfaces(self.find_dumpcap())
            return True
        except (OSError, subprocess.SubprocessError, RuntimeError):
            return False


def _interfaces(tool: Path) -> list[dict[str, str]]:
    result = subprocess.run(
        [str(tool), "-D"],
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    diagnostic = f"{result.stdout}\n{result.stderr}".strip()
    if "Unable to load Npcap" in diagnostic or "wpcap.dll" in diagnostic:
        raise NpcapUnavailableError(
            "dumpcap was found, but Npcap could not be loaded. Repair or reinstall "
            "the matching Npcap package, restart Windows, then run dumpcap -D again."
        )
    if result.returncode:
        raise RuntimeError(
            f"dumpcap failed to list interfaces ({result.returncode}): {diagnostic[:2000]}"
        )
    return [
        {"index": line.split(".", 1)[0], "name": line.split(".", 1)[1].strip()}
        for line in result.stdout.splitlines()
        if "." in line
    ]
