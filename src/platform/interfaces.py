"""Safe, locale-independent interface listing for configured capture tools."""
from __future__ import annotations

import subprocess
from pathlib import Path


def decode_command_output(value: bytes | str | None) -> str:
    """Decode tool output as UTF-8 without relying on the Windows ANSI code page."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode("utf-8", errors="replace")


def list_dumpcap_interfaces(executable: Path) -> list[dict[str, str]]:
    """Run a configured dumpcap executable and parse its interface listing."""
    result = subprocess.run(
        [str(executable), "-D"],
        shell=False,
        check=False,
        capture_output=True,
        timeout=10,
    )
    stdout = decode_command_output(result.stdout)
    stderr = decode_command_output(result.stderr)
    if result.returncode:
        diagnostic = f"{stdout}\n{stderr}".strip()
        raise RuntimeError(
            f"dumpcap failed to list interfaces ({result.returncode}): {diagnostic[:2000]}"
        )
    return [
        {"index": line.split(".", 1)[0], "name": line.split(".", 1)[1].strip()}
        for line in stdout.splitlines()
        if "." in line
    ]
