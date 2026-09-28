"""Safe interface listing for explicitly configured capture tools."""
from __future__ import annotations

import subprocess
from pathlib import Path


def list_dumpcap_interfaces(executable: Path) -> list[dict[str, str]]:
    """Run a configured dumpcap executable and parse its interface listing."""
    result = subprocess.run(
        [str(executable), "-D"],
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode:
        diagnostic = f"{result.stdout}\n{result.stderr}".strip()
        raise RuntimeError(
            f"dumpcap failed to list interfaces ({result.returncode}): {diagnostic[:2000]}"
        )
    return [
        {"index": line.split(".", 1)[0], "name": line.split(".", 1)[1].strip()}
        for line in result.stdout.splitlines()
        if "." in line
    ]
