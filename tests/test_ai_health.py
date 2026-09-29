import httpx
import pytest

from src.ai.client import HTTPAIClient
from src.ai.client import _validation_failure
from src.ai.health import check_ai
from src.config import AIConfig
from src.models import EndpointAnalysisResult
from src.models import EndpointAnalysisRequest
from pydantic import ValidationError


def test_check_ai_rejects_disabled_or_incomplete_configuration():
    assert check_ai(AIConfig())["error"] == "AI is disabled in configuration"
    assert check_ai(AIConfig(enabled=True, model="model"))["error"] == "ai.base_url is empty"
    assert check_ai(AIConfig(enabled=True, base_url="http://localhost/v1"))["error"] == "ai.model is empty"


def test_validation_failure_reports_schema_location_without_input():
    with pytest.raises(ValidationError) as caught:
        EndpointAnalysisResult.model_validate({"request_schema": {"secret": "do-not-log"}})
    message = _validation_failure(caught.value)
    assert "normalized_path:missing" in message
    assert "confidence:missing" in message
    assert "do-not-log" not in message


def test_check_ai_uses_synthetic_evidence_and_reports_structured_output(monkeypatch):
    captured = {}

    def analyze(_client, request):
        captured["request"] = request
        return EndpointAnalysisResult(
            normalized_path=request.normalized_path,
            request_schema={},
            responses={},
            confidence=0.9,
        )

    monkeypatch.setattr("src.ai.health.HTTPAIClient.analyze_endpoint", analyze)
    result = check_ai(
        AIConfig(
            enabled=True,
            model="local-model",
            base_url="http://127.0.0.1:8000/v1",
            api_key_env="",
        )
    )
    assert result == {
        "healthy": True,
        "model": "local-model",
        "endpoint": "http://127.0.0.1:8000/v1/chat/completions",
        "authenticated": False,
        "proxyConfigured": False,
        "tlsVerified": True,
        "syntheticEvidence": True,
        "structuredOutputValid": True,
        "normalizedPath": "/__api_survey_health__",
        "confidence": 0.9,
    }
    assert captured["request"].host == "ai-healthcheck.invalid"
    assert captured["request"].samples == []


def test_check_ai_passes_explicit_environment_proxy_policy(monkeypatch):
    captured = {}

    def analyze(client, request):
        captured["trust_env_proxy"] = client.trust_env_proxy
        return EndpointAnalysisResult(
            normalized_path=request.normalized_path, confidence=1.0
        )

    monkeypatch.setattr("src.ai.health.HTTPAIClient.analyze_endpoint", analyze)
    result = check_ai(
        AIConfig(
            enabled=True,
            model="remote-model",
            base_url="https://ai.example.test/v1",
            api_key_env="",
            trust_env_proxy=True,
        )
    )
    assert result["healthy"] is True
    assert captured["trust_env_proxy"] is True


def test_check_ai_returns_secret_free_failure(monkeypatch):
    def fail(_client, _request):
        raise RuntimeError("FAILED_AI_PARSE")

    monkeypatch.setattr("src.ai.health.HTTPAIClient.analyze_endpoint", fail)
    result = check_ai(
        AIConfig(
            enabled=True,
            model="model",
            base_url="https://ai.example.test/v1",
            api_key_env="AI_API_KEY",
        )
    )
    assert result == {
        "healthy": False,
        "model": "model",
        "endpoint": "https://ai.example.test/v1/chat/completions",
        "authenticated": True,
        "proxyConfigured": False,
        "tlsVerified": True,
        "syntheticEvidence": True,
        "error": "FAILED_AI_PARSE",
    }


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (httpx.ConnectError("refused"), "CONNECTION_ERROR_ConnectError"),
        (httpx.TimeoutException("slow"), "TIMEOUT"),
    ],
)
def test_ai_client_reports_safe_transport_failure(monkeypatch, failure, expected):
    monkeypatch.setattr(
        "src.ai.client.httpx.post", lambda *args, **kwargs: (_ for _ in ()).throw(failure)
    )
    client = HTTPAIClient("http://127.0.0.1:8000/v1", "qwen", "", retries=0)
    with pytest.raises(RuntimeError, match=expected):
        client.analyze_endpoint(
            EndpointAnalysisRequest(
                host="test", method="GET", normalized_path="/test", samples=[]
            )
        )


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", "CERTIFICATE_VERIFY"),
        ("[Errno 11001] getaddrinfo failed", "CONNECTION_ERROR_DNS"),
        ("[WinError 10061] target machine actively refused it", "CONNECTION_ERROR_REFUSED"),
        ("[Errno 101] Network is unreachable", "CONNECTION_ERROR_NETWORK_UNREACHABLE"),
    ],
)
def test_ai_client_classifies_safe_connection_details(monkeypatch, message, expected):
    failure = httpx.ConnectError(message)
    monkeypatch.setattr(
        "src.ai.client.httpx.post", lambda *args, **kwargs: (_ for _ in ()).throw(failure)
    )
    client = HTTPAIClient("https://private.example/v1", "qwen", "", retries=0)
    with pytest.raises(RuntimeError, match=expected):
        client.analyze_endpoint(
            EndpointAnalysisRequest(
                host="test", method="GET", normalized_path="/test", samples=[]
            )
        )


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("407 Proxy Authentication Required", "PROXY_AUTH_REQUIRED"),
        ("403 Forbidden", "PROXY_FORBIDDEN"),
        ("502 Bad Gateway", "PROXY_UPSTREAM_ERROR"),
        ("proxy disconnected", "CONNECTION_ERROR_ProxyError"),
    ],
)
def test_ai_client_classifies_proxy_failures(monkeypatch, message, expected):
    failure = httpx.ProxyError(message)
    monkeypatch.setattr(
        "src.ai.client.httpx.post", lambda *args, **kwargs: (_ for _ in ()).throw(failure)
    )
    client = HTTPAIClient("https://private.example/v1", "qwen", "", retries=0)
    with pytest.raises(RuntimeError, match=expected):
        client.analyze_endpoint(
            EndpointAnalysisRequest(
                host="test", method="GET", normalized_path="/test", samples=[]
            )
        )


def test_ai_client_reports_http_status_without_response_body(monkeypatch):
    request = httpx.Request("POST", "http://127.0.0.1:8000/v1/chat/completions")
    response = httpx.Response(400, request=request, text="sensitive provider details")

    def post(*args, **kwargs):
        return response

    monkeypatch.setattr("src.ai.client.httpx.post", post)
    client = HTTPAIClient("http://127.0.0.1:8000/v1", "qwen", "", retries=0)
    with pytest.raises(RuntimeError, match="HTTP_STATUS_400") as error:
        client.analyze_endpoint(
            EndpointAnalysisRequest(
                host="test", method="GET", normalized_path="/test", samples=[]
            )
        )
    assert "sensitive provider details" not in str(error.value)


def test_ai_health_endpoint_omits_url_credentials_and_query(monkeypatch):
    def fail(_client, _request):
        raise RuntimeError("FAILED_AI_PARSE: CONNECTION_ERROR_ConnectError")

    monkeypatch.setattr("src.ai.health.HTTPAIClient.analyze_endpoint", fail)
    result = check_ai(
        AIConfig(
            enabled=True,
            model="qwen",
            base_url="http://user:secret@127.0.0.1:8000/v1?token=hidden",
            api_key_env="",
        )
    )
    assert result["endpoint"] == "http://127.0.0.1:8000/v1/chat/completions"
    assert "secret" not in str(result)
    assert "hidden" not in str(result)
