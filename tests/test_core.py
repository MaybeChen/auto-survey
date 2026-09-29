import json,sqlite3
from pathlib import Path
from unittest.mock import patch
import pytest
from pydantic import ValidationError
from src.ai.analyzer import deterministic_analysis
from src.ai.client import HTTPAIClient
from src.capture.dumpcap import DumpcapBackend
from src.capture.scanner import CaptureScanner
from src.config import AnalysisConfig, AppConfig, load_config
from src.database import Database
from src.endpoint.cluster import group_transactions
from src.endpoint.ignore import should_ignore_transaction
from src.endpoint.normalizer import normalize_path,path_matches
from src.endpoint.samples import observe_fields
from src.models import EndpointAnalysisRequest,EndpointAnalysisResult,HTTPRequest,HTTPResponse,Transaction,CaptureStatus
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

def test_database_defaults_enabled_and_scanner_emits_once(tmp_path):
    config = AppConfig()
    assert config.database.enabled is True
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"pcap")
    scanner = CaptureScanner(tmp_path, stable_seconds=0)
    assert scanner.scan() == []
    assert scanner.scan() == [capture]
    assert scanner.scan() == []


def test_ai_configuration_reads_transport_settings_without_a_secret(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """\
ai:
  enabled: true
  provider: openai-compatible
  model: survey-model
  base_url: https://ai.example.test/v1
  api_key_env: SURVEY_AI_KEY
  retries: 3
""",
        encoding="utf-8",
    )
    config = load_config(config_file)
    assert config.ai.enabled is True
    assert config.ai.model == "survey-model"
    assert config.ai.base_url == "https://ai.example.test/v1"
    assert config.ai.api_key_env == "SURVEY_AI_KEY"
    assert config.ai.retries == 3
    assert config.ai.trust_env_proxy is False
    assert config.ai.proxy_url_env == ""
    assert config.ai.tls_verify is True
    assert config.ai.ca_bundle is None
    assert config.ai.send_response_format is True


def test_ai_client_supports_explicit_anonymous_self_hosted_service(monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "normalized_path": "/health",
                                    "request_schema": {},
                                    "responses": {},
                                    "confidence": 1.0,
                                }
                            )
                        }
                    }
                ]
            }

    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr("src.ai.client.httpx.post", fake_post)
    client = HTTPAIClient("http://127.0.0.1:8000/v1", "local-model", "")
    result = client.analyze_endpoint(
        EndpointAnalysisRequest(
            host="localhost", method="GET", normalized_path="/health", samples=[]
        )
    )
    assert result.normalized_path == "/health"
    assert captured["url"] == "http://127.0.0.1:8000/v1/chat/completions"
    assert captured["headers"] == {"Content-Type": "application/json"}
    assert captured["trust_env"] is False
    assert captured["verify"] is True
    assert captured["json"]["stream"] is False


def test_ai_client_can_omit_unsupported_response_format(monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [{"message": {"content": json.dumps({
                    "normalized_path": "/health", "confidence": 1.0
                })}}]
            }

    captured = {}

    def fake_post(_url, **kwargs):
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr("src.ai.client.httpx.post", fake_post)
    client = HTTPAIClient(
        "https://ai.example.test/v1",
        "qwen",
        "",
        retries=0,
        send_response_format=False,
    )
    client.analyze_endpoint(
        EndpointAnalysisRequest(
            host="test", method="GET", normalized_path="/health", samples=[]
        )
    )
    assert captured["json"]["stream"] is False
    assert "response_format" not in captured["json"]
    system_prompt = captured["json"]["messages"][0]["content"]
    assert '"normalized_path"' in system_prompt
    assert '"confidence"' in system_prompt


def test_ai_client_accepts_valid_json_in_markdown_fence(monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            content = json.dumps({
                "normalized_path": "/health",
                "request_schema": {},
                "responses": {},
                "confidence": 0.8,
            })
            return {"choices": [{"message": {"content": f"```json\n{content}\n```"}}]}

    monkeypatch.setattr("src.ai.client.httpx.post", lambda *_args, **_kwargs: Response())
    client = HTTPAIClient(
        "https://ai.example.test/v1", "qwen", "", retries=0,
        send_response_format=False,
    )
    result = client.analyze_endpoint(
        EndpointAnalysisRequest(
            host="test", method="GET", normalized_path="/health", samples=[]
        )
    )
    assert result.normalized_path == "/health"
    assert result.confidence == 0.8


def test_ai_client_uses_proxy_from_named_environment_variable(monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": json.dumps({
                "normalized_path": "/health", "confidence": 1.0
            })}}]}

    captured = {}
    monkeypatch.setenv("SURVEY_PROXY", "http://proxy.example.test:8080")

    def fake_post(_url, **kwargs):
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr("src.ai.client.httpx.post", fake_post)
    client = HTTPAIClient(
        "https://ai.example.test/v1",
        "qwen",
        "",
        retries=0,
        proxy_url_env="SURVEY_PROXY",
    )
    client.analyze_endpoint(
        EndpointAnalysisRequest(
            host="test", method="GET", normalized_path="/health", samples=[]
        )
    )
    assert captured["proxy"] == "http://proxy.example.test:8080"
    assert captured["trust_env"] is False


def test_ai_client_supports_explicit_tls_policy(monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": json.dumps({
                "normalized_path": "/health", "confidence": 1.0
            })}}]}

    captured = {}

    def fake_post(_url, **kwargs):
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr("src.ai.client.httpx.post", fake_post)
    client = HTTPAIClient(
        "https://ai.example.test/v1",
        "qwen",
        "",
        retries=0,
        tls_verify=False,
    )
    client.analyze_endpoint(
        EndpointAnalysisRequest(
            host="test", method="GET", normalized_path="/health", samples=[]
        )
    )
    assert captured["verify"] is False


def test_ai_client_adds_enterprise_ca_to_default_tls_context(monkeypatch, tmp_path):
    from src.ai.client import _tls_verifier

    bundle = tmp_path / "enterprise-ca.pem"
    bundle.write_text("test certificate placeholder", encoding="utf-8")
    class Context:
        def __init__(self):
            self.cafile = None

        def load_verify_locations(self, *, cafile):
            self.cafile = cafile

    context = Context()

    monkeypatch.setattr("src.ai.client.ssl.create_default_context", lambda: context)
    result = _tls_verifier(True, str(bundle))
    assert result is context
    assert context.cafile == str(bundle)


def test_ai_client_requires_configured_environment_variable(monkeypatch):
    monkeypatch.delenv("MISSING_SURVEY_KEY", raising=False)
    client = HTTPAIClient("https://ai.example.test/v1", "model", "MISSING_SURVEY_KEY")
    with pytest.raises(RuntimeError, match="MISSING_SURVEY_KEY"):
        client.analyze_endpoint(
            EndpointAnalysisRequest(
                host="example.test", method="GET", normalized_path="/health", samples=[]
            )
        )


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


def test_static_resource_filter_is_configurable_and_case_insensitive():
    config = AnalysisConfig()
    assert should_ignore_transaction(sample_tx("/favicon.ico"), config)
    assert should_ignore_transaction(
        sample_tx("/.well-known/appspecific/com.chrome.devtools.json"), config
    )
    assert should_ignore_transaction(sample_tx("/assets/app.min.JS"), config)
    assert not should_ignore_transaction(sample_tx("/api/users.json"), config)
    assert not should_ignore_transaction(sample_tx("/users/1001"), config)

    custom = AnalysisConfig(ignore_paths=["/static/*"], ignore_extensions=[])
    assert should_ignore_transaction(sample_tx("/STATIC/logo.bin"), custom)
    disabled = AnalysisConfig(ignore_paths=[], ignore_extensions=[])
    assert not should_ignore_transaction(sample_tx("/favicon.ico"), disabled)

def test_interface_records_request_body_presence() -> None:
    without_body = Transaction(
        id="without-body",
        request=HTTPRequest(frame=1, method="GET", host="api.test", path="/health"),
        response=HTTPResponse(frame=2, status=200, body={"ok": True}),
    )
    empty_body = Transaction(
        id="empty-body",
        request=HTTPRequest(
            frame=3, method="POST", host="api.test", path="/objects", body={}
        ),
        response=HTTPResponse(frame=4, status=200, body={"ok": True}),
    )
    from src.validator.validator import validate_analysis

    for transaction, expected in ((without_body, False), (empty_body, True)):
        group = group_transactions([transaction])[0]
        result = deterministic_analysis(group)
        validation = validate_analysis(group, result)
        document = build_interface(group, result, validation)
        assert document["request"]["bodyObserved"] is expected
        assert document["request"]["example"] == transaction.request.body


def test_ai_result_validation_interface_and_openapi(tmp_path):
    with pytest.raises(ValidationError): EndpointAnalysisResult(normalized_path="/x",confidence=2)
    group=group_transactions([sample_tx()])[0]; result=deterministic_analysis(group)
    from src.validator.validator import validate_analysis
    validation=validate_analysis(group,result); assert validation["issues"]==[]
    document=build_interface(group,result,validation); assert document["responses"]["200"]["example"]=={"id":123,"ok":True}
    assert document["request"]["bodyObserved"] is True
    spec=generate_openapi([document],tmp_path); assert spec["openapi"]=="3.1.0"; assert (tmp_path/"openapi.yaml").exists()


def test_interface_preserves_ai_field_descriptions() -> None:
    from src.validator.validator import validate_analysis

    group = group_transactions([sample_tx()])[0]
    result = deterministic_analysis(group).model_copy(
        update={"field_descriptions": {"request.profile.name": "Display name"}}
    )
    document = build_interface(group, result, validate_analysis(group, result))
    assert document["fieldDescriptions"] == {
        "request.profile.name": "Display name"
    }

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
    run_id = db.start_run(ident)
    db.set_capture_status(ident,CaptureStatus.PARSING); assert db.recover_interrupted()==1
    status=db.connection.execute("SELECT status FROM capture_file WHERE id=?",(ident,)).fetchone()[0]; assert status=="STABLE"
    run = db.connection.execute(
        "SELECT status,error,finished_at FROM analysis_run WHERE id=?", (run_id,)
    ).fetchone()
    assert run["status"] == "FAILED"
    assert run["error"] == "recovered after interrupted run"
    assert run["finished_at"] is not None


def test_database_aggregates_endpoint_samples_across_captures(tmp_path):
    database = Database(tmp_path / "agent.db")
    capture_one = tmp_path / "one.pcapng"
    capture_two = tmp_path / "two.pcapng"
    capture_one.write_bytes(b"one")
    capture_two.write_bytes(b"two")
    capture_one_id, _ = database.register_capture(capture_one)
    capture_two_id, _ = database.register_capture(capture_two)
    first = sample_tx("/users/1001")
    second = sample_tx("/users/1002")
    first.id = "capture-one:first"
    second.id = "capture-two:second"
    group = group_transactions([first, second])[0]
    endpoint_id = database.upsert_endpoint(group)
    database.save_transaction(capture_one_id, first)
    database.save_transaction(capture_two_id, second)
    database.add_endpoint_sample(endpoint_id, first.id)
    database.add_endpoint_sample(endpoint_id, second.id)

    persisted = database.load_endpoint_groups(max_samples=20)
    assert len(persisted) == 1
    assert persisted[0][0] == endpoint_id
    assert [sample.request.path for sample in persisted[0][1].samples] == [
        "/users/1001",
        "/users/1002",
    ]
    sample_count = database.connection.execute(
        "SELECT sample_count FROM endpoint WHERE id=?", (endpoint_id,)
    ).fetchone()[0]
    assert sample_count == 2
    report = database.status_report()
    assert report["captureFiles"] == [{"status": "DISCOVERED", "count": 2}]
    assert report["endpoints"] == [{"status": "DISCOVERED", "count": 1}]


def test_configured_dumpcap_interface_parser(monkeypatch):
    from subprocess import CompletedProcess
    from src.platform.interfaces import list_dumpcap_interfaces

    monkeypatch.setattr(
        "src.platform.interfaces.subprocess.run",
        lambda *args, **kwargs: CompletedProcess(
            args[0], 0, "1. Ethernet\n2. Wi-Fi\n", ""
        ),
    )
    assert list_dumpcap_interfaces(Path("D:/Wireshark/dumpcap.exe")) == [
        {"index": "1", "name": "Ethernet"},
        {"index": "2", "name": "Wi-Fi"},
    ]


def test_dumpcap_interface_output_is_decoded_without_windows_locale(monkeypatch):
    from subprocess import CompletedProcess
    from src.platform.interfaces import list_dumpcap_interfaces

    output = "1. 以太网\n2. Wi-Fi €\n".encode("utf-8") + b"3. device-\xac\n"
    monkeypatch.setattr(
        "src.platform.interfaces.subprocess.run",
        lambda *args, **kwargs: CompletedProcess(args[0], 0, output, b""),
    )
    interfaces = list_dumpcap_interfaces(Path("D:/Wireshark/dumpcap.exe"))
    assert interfaces[0] == {"index": "1", "name": "以太网"}
    assert interfaces[1] == {"index": "2", "name": "Wi-Fi €"}
    assert interfaces[2]["name"] == "device-�"


def test_dumpcap_none_stdout_does_not_crash(monkeypatch):
    from subprocess import CompletedProcess
    from src.platform.interfaces import list_dumpcap_interfaces

    monkeypatch.setattr(
        "src.platform.interfaces.subprocess.run",
        lambda *args, **kwargs: CompletedProcess(args[0], 0, None, None),
    )
    assert list_dumpcap_interfaces(Path("D:/Wireshark/dumpcap.exe")) == []
