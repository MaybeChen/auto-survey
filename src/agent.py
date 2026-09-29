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
from src.endpoint.cluster import EndpointGroup, group_transactions
from src.endpoint.ignore import should_ignore_transaction
from src.endpoint.samples import observe_fields
from src.models import CaptureStatus
from src.output.atomic import atomic_write_text
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
    """Return a stable SHA256 identifier without requiring persistent state."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_capture_path(path: Path) -> None:
    """Raise an actionable error for a missing or unsupported capture input."""
    if path.suffix.lower() not in {".pcap", ".pcapng"}:
        raise ValueError(
            f"unsupported capture extension {path.suffix!r}; expected .pcap or .pcapng: {path}"
        )
    if path.is_file():
        return
    parent = path.parent
    nearby: list[str] = []
    if parent.is_dir():
        candidates = sorted(
            (*parent.glob("*.pcap"), *parent.glob("*.pcapng")),
            key=lambda item: item.stat().st_mtime_ns,
            reverse=True,
        )
        nearby = [candidate.name for candidate in candidates[:5]]
    detail = f"; newest captures in that directory: {nearby}" if nearby else ""
    raise FileNotFoundError(f"capture file does not exist: {path}{detail}")


def analyze_file(pcap: Path, config: AppConfig, force: bool = False) -> list[dict[str, Any]]:
    """Analyze a capture and merge its redacted evidence into persistent endpoints."""
    _validate_capture_path(pcap)

    paths = config.create_directories()
    database = _optional_database(config, paths["state"])
    capture_key = _capture_key(pcap)
    capture_id: int | None = None
    run_id: int | None = None
    if database is not None:
        database.recover_interrupted()
        capture_id, should_process = database.register_capture(pcap, force)
        if not should_process:
            LOG.info("capture already processed: %s", pcap)
            return []
        run_id = database.start_run(capture_id)
    elif force:
        LOG.debug("--force has no effect while database persistence is disabled")

    def set_status(
        status: CaptureStatus,
        error: str | None = None,
        stats: dict[str, int] | None = None,
    ) -> None:
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
            if database is not None and run_id is not None:
                database.finish_run(run_id, status.value)
            return []

        set_status(CaptureStatus.PARSING)
        packets = extract_http1(runner, pcap)
        captured_transactions = build_transactions(packets)
        transactions = [
            transaction
            for transaction in captured_transactions
            if not should_ignore_transaction(transaction, config.analysis)
        ]
        ignored_transaction_count = len(captured_transactions) - len(transactions)
        if ignored_transaction_count:
            LOG.info(
                "ignored %s configured static-resource transactions",
                ignored_transaction_count,
            )
        # Frame/stream IDs restart in every capture; namespace transaction IDs by capture.
        for transaction in transactions:
            transaction.id = f"{capture_key}:{transaction.id}"
        redacted = [
            redact_transaction(
                transaction,
                config.redaction.headers,
                config.redaction.json_fields,
                config.redaction.replacement,
            )
            for transaction in transactions
        ]
        current_groups = group_transactions(
            redacted, config.analysis.max_samples_per_endpoint
        )
        current_keys = {group.key for group in current_groups}

        endpoint_groups: list[tuple[int | None, EndpointGroup]]
        if database is not None and capture_id is not None:
            for transaction in redacted:
                database.save_transaction(capture_id, transaction)
            for group in current_groups:
                endpoint_id = database.upsert_endpoint(group)
                for transaction in group.samples:
                    database.add_endpoint_sample(endpoint_id, transaction.id)
            endpoint_groups = [
                (endpoint_id, group)
                for endpoint_id, group in database.load_endpoint_groups(
                    config.analysis.max_samples_per_endpoint
                )
                if any(
                    not should_ignore_transaction(sample, config.analysis)
                    for sample in group.samples
                )
            ]
        else:
            endpoint_groups = [(None, group) for group in current_groups]

        redacted_file = paths["redacted"] / f"capture-{capture_key[:16]}.json"
        atomic_write_text(
            redacted_file,
            json.dumps(
                [item.model_dump(mode="json") for item in redacted],
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
        )
        set_status(CaptureStatus.PARSED, stats=stats)
        set_status(CaptureStatus.ANALYZING, stats=stats)
        client = (
            HTTPAIClient(
                config.ai.base_url,
                config.ai.model,
                config.ai.api_key_env,
                config.ai.retries,
                config.ai.trust_env_proxy,
                config.ai.proxy_url_env,
                config.ai.tls_verify,
                str(config.ai.ca_bundle) if config.ai.ca_bundle else None,
                config.ai.send_response_format,
            )
            if config.ai.enabled
            else None
        )
        documents: list[tuple[Path, dict[str, Any]]] = []
        current_pending = False
        for endpoint_id, group in endpoint_groups:
            try:
                result = analyze(group, client)
            except Exception as exc:
                if database is not None and endpoint_id is not None:
                    database.save_ai_analysis(endpoint_id, None, str(exc))
                raise
            validation = validate_analysis(group, result)
            document = build_interface(group, result, validation)
            output_file = write_interface(paths["interfaces"], document)
            documents.append((output_file, document))
            pending = (
                validation["confidence"] < config.analysis.publish_confidence
                or len(group.samples) < config.analysis.min_samples
            )
            if group.key in current_keys:
                current_pending = current_pending or pending
            if database is not None and endpoint_id is not None:
                database.update_endpoint(
                    endpoint_id,
                    CaptureStatus.PENDING_MORE_SAMPLES if pending else CaptureStatus.DONE,
                    validation["confidence"],
                )
                database.save_observations(
                    endpoint_id,
                    "request.body",
                    observe_fields([sample.request.body for sample in group.samples]),
                )
                database.save_ai_analysis(endpoint_id, result)

        generated_interface_files = {path.resolve() for path, _ in documents}
        for existing in paths["interfaces"].glob("*.json"):
            if existing.resolve() not in generated_interface_files:
                existing.unlink()
        output_root = paths["interfaces"].parent
        write_catalog(output_root, documents)
        if config.output.generate_openapi:
            generate_openapi(
                [document for _, document in documents], paths["openapi"]
            )
        summary = {
            "capture": pcap.name,
            "captureSha256": capture_key,
            "protocols": stats,
            "capturedTransactionCount": len(captured_transactions),
            "ignoredTransactionCount": ignored_transaction_count,
            "transactionCount": len(transactions),
            "endpointCount": len(documents),
            "databaseEnabled": database is not None,
        }
        atomic_write_text(
            paths["reports"] / "analysis-summary.json",
            json.dumps(summary, indent=2) + "\n",
        )
        final_status = (
            CaptureStatus.PENDING_MORE_SAMPLES if current_pending else CaptureStatus.DONE
        )
        set_status(final_status)
        if database is not None and run_id is not None:
            database.finish_run(run_id, final_status.value)
        return [document for _, document in documents]
    except Exception as exc:
        set_status(CaptureStatus.FAILED, error=str(exc))
        if database is not None and run_id is not None:
            database.finish_run(run_id, "FAILED", str(exc))
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
