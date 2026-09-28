"""Vendor-neutral OpenAI-compatible structured JSON transport."""
from __future__ import annotations

import json
import os

import httpx

from src.models import EndpointAnalysisRequest, EndpointAnalysisResult

from .base import AIClient


class HTTPAIClient(AIClient):
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key_env: str = "AI_API_KEY",
        retries: int = 2,
        trust_env_proxy: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key_env = api_key_env
        self.retries = retries
        self.trust_env_proxy = trust_env_proxy

    def analyze_endpoint(
        self, request: EndpointAnalysisRequest
    ) -> EndpointAnalysisResult:
        """Analyze redacted evidence and validate the provider's structured result."""
        key = os.environ.get(self.api_key_env) if self.api_key_env else None
        if self.api_key_env and not key:
            raise RuntimeError(
                f"AI API key environment variable {self.api_key_env} is not set"
            )
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        payload = request.model_dump(mode="json")
        # This boundary receives redacted samples only; it has no filesystem API.
        messages = [
            {
                "role": "system",
                "content": (
                    "Infer an API schema only from evidence. Return JSON matching "
                    "EndpointAnalysisResult; never invent fields."
                ),
            },
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ]
        failure = "UNKNOWN_ERROR"
        for _ in range(self.retries + 1):
            try:
                response = httpx.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json={
                        "model": self.model,
                        "messages": messages,
                        "response_format": {"type": "json_object"},
                    },
                    timeout=60,
                    trust_env=self.trust_env_proxy,
                )
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                return EndpointAnalysisResult.model_validate_json(content)
            except httpx.HTTPStatusError as exc:
                failure = f"HTTP_STATUS_{exc.response.status_code}"
            except httpx.TimeoutException:
                failure = "TIMEOUT"
            except httpx.RequestError as exc:
                failure = f"CONNECTION_ERROR_{type(exc).__name__}"
            except (KeyError, IndexError, TypeError):
                failure = "INVALID_CHAT_COMPLETIONS_RESPONSE"
            except ValueError as exc:
                failure = f"INVALID_STRUCTURED_OUTPUT_{type(exc).__name__}"
        raise RuntimeError(f"FAILED_AI_PARSE: {failure}")
