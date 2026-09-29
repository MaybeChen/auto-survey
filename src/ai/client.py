"""Vendor-neutral OpenAI-compatible structured JSON transport."""
from __future__ import annotations

import json
import logging
import os
import ssl

import httpx
from pydantic import ValidationError

from src.models import EndpointAnalysisRequest, EndpointAnalysisResult

from .base import AIClient

LOG = logging.getLogger(__name__)


def _validate_structured_content(content: str) -> EndpointAnalysisResult:
    """Validate JSON content, accepting a single common Markdown JSON fence."""
    try:
        return EndpointAnalysisResult.model_validate_json(content)
    except ValidationError:
        cleaned = content.strip()
        if cleaned.startswith("```") and cleaned.endswith("```"):
            first_newline = cleaned.find("\n")
            if first_newline != -1:
                cleaned = cleaned[first_newline + 1 : -3].strip()
                return EndpointAnalysisResult.model_validate_json(cleaned)
        raise


def _validation_failure(exc: ValidationError) -> str:
    """Summarize validation locations and types without exposing model content."""
    issues = []
    for error in exc.errors(include_input=False)[:5]:
        location = ".".join(str(part) for part in error["loc"]) or "root"
        issues.append(f"{location}:{error['type']}")
    return "INVALID_STRUCTURED_OUTPUT_ValidationError[" + ",".join(issues) + "]"


def _tls_verifier(tls_verify: bool, ca_bundle: str | None) -> bool | ssl.SSLContext:
    """Build secure defaults and optionally add an enterprise CA bundle."""
    if not ca_bundle:
        return tls_verify
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=ca_bundle)
    return context


def _request_failure(exc: httpx.RequestError) -> str:
    """Classify a transport exception without exposing URLs or credentials."""
    detail = str(exc).casefold()
    if isinstance(exc, httpx.ProxyError):
        if "407" in detail:
            return "PROXY_AUTH_REQUIRED"
        if "403" in detail:
            return "PROXY_FORBIDDEN"
        if "502" in detail or "503" in detail or "504" in detail:
            return "PROXY_UPSTREAM_ERROR"
        return "CONNECTION_ERROR_ProxyError"
    if "certificate verify failed" in detail or "certificateverifyfailed" in detail:
        return "CONNECTION_ERROR_CERTIFICATE_VERIFY"
    if "name or service not known" in detail or "getaddrinfo failed" in detail:
        return "CONNECTION_ERROR_DNS"
    if "connection refused" in detail or "actively refused" in detail:
        return "CONNECTION_ERROR_REFUSED"
    if "network is unreachable" in detail or "no route to host" in detail:
        return "CONNECTION_ERROR_NETWORK_UNREACHABLE"
    return f"CONNECTION_ERROR_{type(exc).__name__}"


class HTTPAIClient(AIClient):
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key_env: str = "AI_API_KEY",
        retries: int = 2,
        trust_env_proxy: bool = False,
        proxy_url_env: str = "",
        tls_verify: bool = True,
        ca_bundle: str | None = None,
        send_response_format: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key_env = api_key_env
        self.retries = retries
        self.trust_env_proxy = trust_env_proxy
        self.proxy_url_env = proxy_url_env
        self.tls_verify = tls_verify
        self.ca_bundle = ca_bundle
        self.send_response_format = send_response_format

    def analyze_endpoint(
        self, request: EndpointAnalysisRequest
    ) -> EndpointAnalysisResult:
        """Analyze redacted evidence and validate the provider's structured result."""
        key = os.environ.get(self.api_key_env) if self.api_key_env else None
        if self.api_key_env and not key:
            raise RuntimeError(
                f"AI API key environment variable {self.api_key_env} is not set"
            )
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        proxy_url = os.environ.get(self.proxy_url_env) if self.proxy_url_env else None
        if self.proxy_url_env and not proxy_url:
            raise RuntimeError(
                f"AI proxy environment variable {self.proxy_url_env} is not set"
            )
        verify = _tls_verifier(self.tls_verify, self.ca_bundle)
        if verify is False:
            LOG.warning("AI TLS certificate and hostname verification are disabled")
        payload = request.model_dump(mode="json")
        # This boundary receives redacted samples only; it has no filesystem API.
        result_schema = json.dumps(
            EndpointAnalysisResult.model_json_schema(), ensure_ascii=False
        )
        messages = [
            {
                "role": "system",
                "content": (
                    "Infer an API schema only from evidence. Return JSON matching "
                    "EndpointAnalysisResult; never invent fields. Return only the JSON "
                    f"object, without Markdown fences. JSON Schema: {result_schema}"
                ),
            },
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ]
        failure = "UNKNOWN_ERROR"
        for _ in range(self.retries + 1):
            try:
                request_json = {
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                }
                if self.send_response_format:
                    request_json["response_format"] = {"type": "json_object"}
                response = httpx.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=request_json,
                    timeout=60,
                    trust_env=self.trust_env_proxy,
                    proxy=proxy_url,
                    verify=verify,
                )
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                return _validate_structured_content(content)
            except httpx.HTTPStatusError as exc:
                failure = f"HTTP_STATUS_{exc.response.status_code}"
            except httpx.TimeoutException:
                failure = "TIMEOUT"
            except httpx.RequestError as exc:
                failure = _request_failure(exc)
            except (KeyError, IndexError, TypeError):
                failure = "INVALID_CHAT_COMPLETIONS_RESPONSE"
            except ValidationError as exc:
                failure = _validation_failure(exc)
            except ValueError as exc:
                failure = f"INVALID_STRUCTURED_OUTPUT_{type(exc).__name__}"
        raise RuntimeError(f"FAILED_AI_PARSE: {failure}")
