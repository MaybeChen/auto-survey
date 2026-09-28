from src.ai.health import check_ai
from src.config import AIConfig
from src.models import EndpointAnalysisResult


def test_check_ai_rejects_disabled_or_incomplete_configuration():
    assert check_ai(AIConfig())["error"] == "AI is disabled in configuration"
    assert check_ai(AIConfig(enabled=True, model="model"))["error"] == "ai.base_url is empty"
    assert check_ai(AIConfig(enabled=True, base_url="http://localhost/v1"))["error"] == "ai.model is empty"


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
        "authenticated": False,
        "structuredOutputValid": True,
        "normalizedPath": "/__api_survey_health__",
        "confidence": 0.9,
    }
    assert captured["request"].host == "ai-healthcheck.invalid"
    assert captured["request"].samples == []


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
        "authenticated": True,
        "error": "FAILED_AI_PARSE",
    }
