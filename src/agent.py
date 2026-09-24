"""End-to-end deterministic orchestration for capture analysis."""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from src.ai.analyzer import analyze
from src.ai.client import HTTPAIClient
from src.capture.scanner import CaptureScanner
from src.config import AppConfig, load_config
from src.database import Database
from src.endpoint.cluster import group_transactions
from src.models import CaptureStatus
from src.output.catalog import write_catalog
from src.output.interface_json import build_interface, write_interface
from src.output.openapi import generate_openapi
from src.platform import get_platform_adapter
from src.redaction.redact import redact_transaction
from src.tshark.http1 import extract_http1
from src.tshark.protocol_probe import probe_protocols
from src.tshark.runner import TsharkRunner
from src.transaction.builder import build_transactions
from src.validator.validator import validate_analysis

LOG = logging.getLogger("api_survey")


def _runner(config: AppConfig) -> TsharkRunner:
    executable = config.tshark.path or get_platform_adapter().find_tshark()
    LOG.info("tshark path: %s", executable)
    return TsharkRunner(executable)


def _optional_database(config: AppConfig, state_dir: Path) -> Database | None:
    """Open SQLite only when explicitly enabled in configuration."""
    if not config.database.enabled:
        return None
    path = Path(config.database.url) if config.database.url else state_dir / "agent.db"
    return Database(path)


def _capture_key(path: Path) -> str:
    """Return a stable short identifier without requiring persistent state."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()[:16]


def analyze_file(pcap: Path, config: AppConfig, force: bool = False) -> list[dict[str, Any]]:
    """Analyze one capture; SQLite persistence is optional and disabled by default."""
    if not pcap.is_file() or pcap.suffix.lower() not in {".pcap", ".pcapng"}:
        raise FileNotFoundError(f"pcap not found or unsupported: {pcap}")

    paths = config.create_directories()
    database = _optional_database(config, paths["state"])
    capture_key = _capture_key(pcap)
    capture_id: int | None = None
    if database is not None:
        capture_id, should_process = database.register_capture(pcap, force)
        if not should_process:
            LOG.info("capture already processed: %s", pcap)
            return []
    elif force:
        LOG.debug("--force has no effect while database persistence is disabled")

    def set_status(status: CaptureStatus, error: str | None = None, stats: dict[str, int] | None = None) -> None:
        if database is not None and capture_id is not None:
            database.set_capture_status(capture_id, status, error=error, stats=stats)

    try:
        runner = _runner(config)
        set_status(CaptureStatus.PROBING)
        stats = probe_protocols(runner, pcap)
        LOG.info("protocol statistics: %s", stats)
        if not stats["http"]:
            status = CaptureStatus.BLOCKED_TLS if stats["tls"] else CaptureStatus.DONE
            set_status(status, stats=stats)
            return []

        set_status(CaptureStatus.PARSING)
        packets = extract_http1(runner, pcap)
        transactions = build_transactions(packets)
        redacted = [
            redact_transaction(
                transaction,
                config.redaction.headers,
                config.redaction.json_fields,
                config.redaction.replacement,
            )
            for transaction in transactions
        ]
        if database is not None and capture_id is not None:
            for transaction in transactions:
                database.save_transaction(capture_id, transaction)

        redacted_file = paths["redacted"] / f"capture-{capture_key}.json"
        redacted_file.write_text(
            json.dumps([item.model_dump(mode="json") for item in redacted], indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        set_status(CaptureStatus.ANALYZING, stats=stats)
        client = (
            HTTPAIClient(
                config.ai.base_url,
                config.ai.model,
                config.ai.api_key_env,
                config.ai.retries,
            )
            if config.ai.enabled
            else None
        )
        documents: list[tuple[Path, dict[str, Any]]] = []
        for group in group_transactions(redacted, config.analysis.max_samples_per_endpoint):
            result = analyze(group, client)
            validation = validate_analysis(group, result)
            document = build_interface(group, result, validation)
            output_file = write_interface(paths["interfaces"], document)
            documents.append((output_file, document))

        output_root = paths["interfaces"].parent
        write_catalog(output_root, documents)
        if config.output.generate_openapi:
            generate_openapi([document for _, document in documents], paths["openapi"])
        summary = {
            "capture": pcap.name,
            "captureSha256": capture_key,
            "protocols": stats,
            "transactionCount": len(transactions),
            "endpointCount": len(documents),
            "databaseEnabled": database is not None,
        }
        (paths["reports"] / "analysis-summary.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8"
        )
        pending = any(
            document["confidence"] < config.analysis.publish_confidence
            or document["statistics"]["sampleCount"] < config.analysis.min_samples
            for _, document in documents
        )
        set_status(CaptureStatus.PENDING_MORE_SAMPLES if pending else CaptureStatus.DONE)
        return [document for _, document in documents]
    except Exception as exc:
        set_status(CaptureStatus.FAILED, error=str(exc))
        LOG.exception("analysis failed for %s", pcap)
        raise


def watch(config: AppConfig, once: bool = False) -> None:
    paths = config.create_directories()
    scanner = CaptureScanner(paths["incoming"], config.capture.stable_seconds)
    while True:
        for path in scanner.scan():
            analyze_file(path, config)
        if once:
            return
        time.sleep(5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--input", type=Path)
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = load_config(args.config)
    if args.input:
        analyze_file(args.input, config)
    else:
        watch(config, args.once)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
