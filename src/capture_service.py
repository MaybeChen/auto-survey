"""Start the configured capture backend without exposing shell execution."""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.capture.dumpcap import DumpcapBackend
from src.capture.tcpdump import TcpdumpBackend
from src.config import AppConfig, load_config
from src.platform import get_platform_adapter

LOG = logging.getLogger("api_survey.capture")


def build_backend(config: AppConfig) -> DumpcapBackend | TcpdumpBackend:
    """Build the configured capture backend using the active platform adapter."""
    adapter = get_platform_adapter()
    if config.capture.backend == "dumpcap":
        executable = config.dumpcap.path or adapter.find_dumpcap()
        return DumpcapBackend(
            executable,
            config.capture.interface,
            config.capture.filter,
            config.capture.duration_seconds,
            config.capture.filesize_kb,
            config.capture.files,
        )
    if config.capture.backend == "tcpdump" and hasattr(adapter, "find_tcpdump"):
        return TcpdumpBackend(
            getattr(adapter, "find_tcpdump")(),
            config.capture.interface,
            config.capture.filter,
        )
    raise ValueError(f"unsupported capture backend on this platform: {config.capture.backend}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="api-survey-capture")
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = load_config(args.config)
    paths = config.create_directories()
    output = paths["incoming"] / "traffic.pcapng"
    backend = build_backend(config)
    LOG.info("starting %s capture into %s", config.capture.backend, output)
    process = backend.start(output)
    return process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
