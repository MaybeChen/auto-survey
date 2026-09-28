"""Safe connectivity check for the configured structured-output AI service."""
from __future__ import annotations

from typing import Any

from src.ai.client import HTTPAIClient
from src.config import AIConfig
from src.models import EndpointAnalysisRequest


def check_ai(config: AIConfig) -> dict[str, Any]:
    """Call the AI service with synthetic evidence and return a secret-free result."""
    if not config.enabled:
        return {"healthy": False, "error": "AI is disabled in configuration"}
    if not config.base_url.strip():
        return {"healthy": False, "error": "ai.base_url is empty"}
    if not config.model.strip():
        return {"healthy": False, "error": "ai.model is empty"}

    client = HTTPAIClient(
        config.base_url,
        config.model,
        config.api_key_env,
        config.retries,
        config.trust_env_proxy,
    )
    request = EndpointAnalysisRequest(
        host="ai-healthcheck.invalid",
        method="GET",
        normalized_path="/__api_survey_health__",
        samples=[],
        observations={},
    )
    try:
        result = client.analyze_endpoint(request)
    except Exception as exc:
        return {
            "healthy": False,
            "model": config.model,
            "authenticated": bool(config.api_key_env),
            "error": str(exc),
        }
    return {
        "healthy": True,
        "model": config.model,
        "authenticated": bool(config.api_key_env),
        "structuredOutputValid": True,
        "normalizedPath": result.normalized_path,
        "confidence": result.confidence,
    }
