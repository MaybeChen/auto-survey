"""Generate OpenAPI documents from validated Standard Interface JSON facts."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

_PATH_PARAMETER = re.compile(r"\{([^{}]+)\}")


def _path_parameters(path: str) -> list[dict[str, Any]]:
    """Return unique OpenAPI path parameters in their first-seen order."""
    seen: set[str] = set()
    parameters: list[dict[str, Any]] = []
    for name in _PATH_PARAMETER.findall(path):
        if name in seen:
            continue
        seen.add(name)
        parameters.append(
            {
                "name": name,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
            }
        )
    return parameters


def _non_blank_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _request_body_was_observed(request: dict[str, Any]) -> bool:
    """Determine body presence without treating valid falsey JSON values as absent.

    New interface documents carry the explicit ``bodyObserved`` fact. For legacy
    documents, a non-None example is the only reliable evidence available. This
    fallback preserves {}, [], 0, false, and "", but legacy JSON null bodies are
    indistinguishable from an unobserved body.
    """
    observed = request.get("bodyObserved")
    if isinstance(observed, bool):
        return observed
    return "example" in request and request["example"] is not None


def generate_openapi(
    interfaces: list[dict[str, Any]], output_dir: Path
) -> dict[str, Any]:
    """Generate and persist OpenAPI 3.1 JSON/YAML from interface facts."""
    servers = sorted({f"http://{item['host']}" for item in interfaces})
    paths: dict[str, Any] = {}
    for item in interfaces:
        request = item["request"]
        operation: dict[str, Any] = {"responses": {}}
        if _non_blank_string(item.get("summary")):
            operation["summary"] = item["summary"]
        if _non_blank_string(item.get("description")):
            operation["description"] = item["description"]

        parameters = _path_parameters(item["path"])
        if parameters:
            operation["parameters"] = parameters

        if _request_body_was_observed(request):
            media: dict[str, Any] = {"schema": request.get("bodySchema", {})}
            if "example" in request:
                media["example"] = request["example"]
            operation["requestBody"] = {
                "content": {
                    request.get("contentType") or "application/json": media,
                }
            }

        for status, response in item["responses"].items():
            operation["responses"][status] = {
                "description": f"Observed HTTP {status}",
                "content": {
                    response.get("contentType") or "application/json": {
                        "schema": response.get("bodySchema", {}),
                        "example": response.get("example"),
                    }
                },
            }
        paths.setdefault(item["path"], {})[item["method"].lower()] = operation

    spec = {
        "openapi": "3.1.0",
        "info": {"title": "Observed API Catalog", "version": "1.0.0"},
        "servers": [{"url": server} for server in servers],
        "paths": paths,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "openapi.json").write_text(
        json.dumps(spec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (output_dir / "openapi.yaml").write_text(
        yaml.safe_dump(spec, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    return spec


def load_interfaces(directory: Path) -> list[dict[str, Any]]:
    """Load Standard Interface JSON documents in deterministic filename order."""
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(directory.glob("*.json"))
    ]
