import json,sqlite3
from pathlib import Path
from unittest.mock import patch
import pytest
from pydantic import ValidationError
from src.ai.analyzer import deterministic_analysis
from src.capture.dumpcap import DumpcapBackend
from src.capture.scanner import CaptureScanner
from src.config import AppConfig
from src.database import Database
from src.endpoint.cluster import group_transactions
from src.endpoint.normalizer import normalize_path,path_matches
from src.endpoint.samples import observe_fields
from src.models import EndpointAnalysisResult,HTTPRequest,HTTPResponse,Transaction,CaptureStatus
from src.output.interface_json import build_interface
from src.output.openapi import generate_openapi
from src.platform.factory import get_platform_adapter
from src.platform.linux import LinuxPlatformAdapter
from src.platform.windows import NpcapUnavailableError, WindowsPlatformAdapter, _interfaces
from src.redaction.redact import redact_transaction
from src.transaction.body_decoder import decode_body
from src.transaction.builder import build_transactions
from src.tshark.http1 import build_http1_args
from src.tshark.protocol_probe import parse_protocol_lines

def packet(**fields): return {"_source":{"layers":fields}}
def sample_tx(path="/users/123",status=200):
    return Transaction(id=path+str(status),tcp_stream=1,request=HTTPRequest(frame=1,method="GET",host="api.test",path=path,body={"password":"secret","profile":{"token":"abc","name":"Ann"}}),response=HTTPResponse(frame=2,status=status,content_type="application/json",body={"id":123,"ok":True}))

def test_platform_factory_and_windows_linux_discovery():
    assert isinstance(get_platform_adapter("Windows"),WindowsPlatformAdapter)
    assert isinstance(get_platform_adapter("Linux"),LinuxPlatformAdapter)
    with patch("src.platform.windows.shutil.which",return_value="C:/Tools/tshark.exe"): assert WindowsPlatformAdapter().find_tshark()==Path("C:/Tools/tshark.exe")
    with patch("src.platform.linux.shutil.which",return_value="/usr/bin/tshark"): assert LinuxPlatformAdapter().find_tshark()==Path("/usr/bin/tshark")

    failed = __import__("subprocess").CompletedProcess(
        ["dumpcap", "-D"], 1, "", "Unable to load Npcap (wpcap.dll)"
    )
    with patch("src.platform.windows.subprocess.run", return_value=failed):
        with pytest.raises(NpcapUnavailableError, match="Npcap could not be loaded"):
            _interfaces(Path("dumpcap.exe"))

def test_database_is_optional_and_scanner_emits_once(tmp_path):
    config = AppConfig()
    assert config.database.enabled is False
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"pcap")
    scanner = CaptureScanner(tmp_path, stable_seconds=0)
    assert scanner.scan() == []
    assert scanner.scan() == [capture]
    assert scanner.scan() == []


def test_command_builders(tmp_path):
    args=build_http1_args(tmp_path/"a.pcapng"); assert args[:3]==["-2","-r",str(tmp_path/"a.pcapng")]; assert "http.request.method" in args
    cap=DumpcapBackend(Path("dumpcap"),"1","tcp port 80",10,20,3).build_command(tmp_path/"x.pcapng")
    assert cap==["dumpcap","-i","1","-f","tcp port 80","-s","0","-B","64","-b","duration:10","-b","filesize:20","-b","files:3","-w",str(tmp_path/"x.pcapng")]

def test_probe_body_and_invalid_json():
    assert parse_protocol_lines("eth:ip:tcp:http\neth:ip:tcp:tls\n")== {"tcp":2,"http":1,"tls":1,"http2":0,"quic":0}
    assert decode_body("7b226f6b223a747275657d","application/json").body=={"ok":True}
    bad=decode_body("7b","application/problem+json"); assert bad.body=={"_raw":"{"}; assert bad.parse_error

def test_matching_uses_request_in_then_stream():
    packets=[packet(**{"frame.number":"1","tcp.stream":"2","http.request.method":"GET","http.request.uri":"/a"}),packet(**{"frame.number":"2","tcp.stream":"2","http.response.code":"201","http.request_in":"1"})]
    tx=build_transactions(packets); assert len(tx)==1 and tx[0].response.status==201

def test_recursive_redaction_normalization_grouping_observation():
    redacted=redact_transaction(sample_tx(),["authorization"],["password","token"])
    assert redacted.request.body=={"password":"***","profile":{"token":"***","name":"Ann"}}
    assert normalize_path("/users/550e8400-e29b-41d4-a716-446655440000")=="/users/{value}"
    assert normalize_path("/orders/2026-09-23/123456")=="/orders/{value}/{value}"
    assert path_matches("/users/{value}","/users/123")
    groups=group_transactions([sample_tx("/users/123"),sample_tx("/users/456")]); assert len(groups)==1; assert groups[0].observed_paths==["/users/123","/users/456"]
    obs=observe_fields([{"language":"en"},{"other":1}]); assert obs["language"]["observedPresence"]==.5; assert obs["language"]["observedTypes"]==["string"]

def test_ai_result_validation_interface_and_openapi(tmp_path):
    with pytest.raises(ValidationError): EndpointAnalysisResult(normalized_path="/x",confidence=2)
    group=group_transactions([sample_tx()])[0]; result=deterministic_analysis(group)
    from src.validator.validator import validate_analysis
    validation=validate_analysis(group,result); assert validation["issues"]==[]
    document=build_interface(group,result,validation); assert document["responses"]["200"]["example"]=={"id":123,"ok":True}
    spec=generate_openapi([document],tmp_path); assert spec["openapi"]=="3.1.0"; assert (tmp_path/"openapi.yaml").exists()

def test_packaged_schema_is_available():
    from importlib.resources import files

    schema = files("src.sql").joinpath("schema.sql").read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS capture_file" in schema
    repository_schema = (Path(__file__).parents[1] / "sql" / "schema.sql").read_text(
        encoding="utf-8"
    )
    assert schema == repository_schema


def test_sqlite_dedup_and_recovery(tmp_path):
    capture=tmp_path/"demo.pcapng"; capture.write_bytes(b"fixture"); db=Database(tmp_path/"agent.db")
    ident,new=db.register_capture(capture); assert new; assert db.register_capture(capture)==(ident,False)
    tx = sample_tx()
    db.save_transaction(ident, tx)
    saved = db.connection.execute('SELECT COUNT(*) FROM "transaction"').fetchone()[0]
    assert saved == 1
    db.set_capture_status(ident,CaptureStatus.PARSING); assert db.recover_interrupted()==1
    status=db.connection.execute("SELECT status FROM capture_file WHERE id=?",(ident,)).fetchone()[0]; assert status=="STABLE"
