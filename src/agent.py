"""End-to-end deterministic orchestration for capture analysis."""
from __future__ import annotations
import argparse,json,logging,time
from pathlib import Path
from src.ai.analyzer import analyze
from src.ai.client import HTTPAIClient
from src.capture.scanner import CaptureScanner
from src.config import AppConfig,load_config
from src.database import Database
from src.endpoint.cluster import group_transactions
from src.models import CaptureStatus
from src.output.catalog import write_catalog
from src.output.interface_json import build_interface,write_interface
from src.output.openapi import generate_openapi
from src.platform import get_platform_adapter
from src.redaction.redact import redact_transaction
from src.tshark.http1 import extract_http1
from src.tshark.protocol_probe import probe_protocols
from src.tshark.runner import TsharkRunner
from src.transaction.builder import build_transactions
LOG=logging.getLogger("api_survey")

def _runner(config:AppConfig)->TsharkRunner:
    executable=config.tshark.path or get_platform_adapter().find_tshark(); LOG.info("tshark path: %s",executable); return TsharkRunner(executable)
def analyze_file(pcap:Path,config:AppConfig,force:bool=False)->list[dict]:
    """Analyze one immutable capture and publish only redacted evidence products."""
    if not pcap.is_file() or pcap.suffix.lower() not in {".pcap",".pcapng"}: raise FileNotFoundError(f"pcap not found or unsupported: {pcap}")
    paths=config.create_directories(); db_path=Path(config.database.url) if config.database.url else paths["state"]/"agent.db"; db=Database(db_path)
    capture_id,should_process=db.register_capture(pcap,force)
    if not should_process: LOG.info("capture already processed: %s",pcap); return []
    try:
        runner=_runner(config); db.set_capture_status(capture_id,CaptureStatus.PROBING); stats=probe_protocols(runner,pcap); LOG.info("protocol statistics: %s",stats)
        if not stats["http"]:
            status=CaptureStatus.BLOCKED_TLS if stats["tls"] else CaptureStatus.DONE; db.set_capture_status(capture_id,status,stats=stats); return []
        db.set_capture_status(capture_id,CaptureStatus.PARSING); packets=extract_http1(runner,pcap); transactions=build_transactions(packets)
        redacted=[redact_transaction(x,config.redaction.headers,config.redaction.json_fields,config.redaction.replacement) for x in transactions]
        for tx in transactions: db.save_transaction(capture_id,tx)
        # Only redacted artifacts proceed across the AI boundary.
        redacted_file=paths["redacted"]/f"capture-{capture_id}.json"; redacted_file.write_text(json.dumps([x.model_dump(mode="json") for x in redacted],indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        db.set_capture_status(capture_id,CaptureStatus.ANALYZING,stats=stats); client=HTTPAIClient(config.ai.base_url,config.ai.model,config.ai.api_key_env,config.ai.retries) if config.ai.enabled else None
        documents=[]
        for group in group_transactions(redacted,config.analysis.max_samples_per_endpoint):
            result=analyze(group,client)
            from src.validator.validator import validate_analysis
            validation=validate_analysis(group,result); document=build_interface(group,result,validation); file=write_interface(paths["interfaces"],document); documents.append((file,document))
        output_root=paths["interfaces"].parent; write_catalog(output_root,documents)
        if config.output.generate_openapi: generate_openapi([x[1] for x in documents],paths["openapi"])
        summary={"capture":pcap.name,"protocols":stats,"transactionCount":len(transactions),"endpointCount":len(documents)}
        (paths["reports"]/"analysis-summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
        pending=any(x[1]["confidence"]<config.analysis.publish_confidence or x[1]["statistics"]["sampleCount"]<config.analysis.min_samples for x in documents)
        db.set_capture_status(capture_id,CaptureStatus.PENDING_MORE_SAMPLES if pending else CaptureStatus.DONE); return [x[1] for x in documents]
    except Exception as exc:
        db.set_capture_status(capture_id,CaptureStatus.FAILED,error=str(exc)); LOG.exception("analysis failed for %s",pcap); raise

def watch(config:AppConfig,once:bool=False)->None:
    paths=config.create_directories(); scanner=CaptureScanner(paths["incoming"],config.capture.stable_seconds)
    while True:
        for path in scanner.scan(): analyze_file(path,config)
        if once:return
        time.sleep(5)
def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(); parser.add_argument("--config",type=Path); parser.add_argument("--once",action="store_true"); parser.add_argument("--input",type=Path); args=parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(name)s %(message)s"); config=load_config(args.config)
    if args.input: analyze_file(args.input,config)
    else: watch(config,args.once)
    return 0
if __name__=="__main__": raise SystemExit(main())
