"""Regression tests for evidence-driven OpenAPI generation."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml
try:
    from openapi_spec_validator import validate_spec
except ImportError:
    validate_spec = None

from src.output.openapi import generate_openapi


def interface(
    *,
    path: str = "/users/{value}",
    method: str = "GET",
    summary: str | None = None,
    description: str | None = None,
    body_observed: bool | None = False,
    example: Any = None,
    body_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "contentType": "application/json",
        "query": {},
        "headers": {},
        "bodySchema": body_schema
        if body_schema is not None
        else {"type": "object", "properties": {}},
        "example": example,
    }
    if body_observed is not None:
        request["bodyObserved"] = body_observed
    return {
        "service": None,
        "host": "api.test",
        "method": method,
        "path": path,
        "summary": summary,
        "description": description,
        "request": request,
        "responses": {
            "200": {
                "contentType": "application/json",
                "bodySchema": {
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                },
                "example": {"ok": True},
            }
        },
    }


def test_path_parameters_are_complete_unique_and_strings(tmp_path: Path) -> None:
    documents = [
        interface(path="/users/{value}"),
        interface(path="/teams/{id}/members/{id}/{memberId}", method="POST"),
        interface(path="/favicon.ico"),
    ]
    spec = generate_openapi(documents, tmp_path)

    assert spec["paths"]["/users/{value}"]["get"]["parameters"] == [
        {
            "name": "value",
            "in": "path",
            "required": True,
            "schema": {"type": "string"},
        }
    ]
    multiple = spec["paths"]["/teams/{id}/members/{id}/{memberId}"]["post"]
    assert [parameter["name"] for parameter in multiple["parameters"]] == [
        "id",
        "memberId",
    ]
    assert all(parameter["schema"] == {"type": "string"} for parameter in multiple["parameters"])
    assert "parameters" not in spec["paths"]["/favicon.ico"]["get"]
    if validate_spec is not None:
        validate_spec(spec)


@pytest.mark.parametrize("value", [None, "", "   \t"])
def test_blank_descriptions_are_omitted(tmp_path: Path, value: str | None) -> None:
    spec = generate_openapi(
        [interface(summary=value, description=value)], tmp_path
    )
    operation = spec["paths"]["/users/{value}"]["get"]
    assert "summary" not in operation
    assert "description" not in operation


def test_valid_descriptions_and_responses_are_preserved(tmp_path: Path) -> None:
    document = interface(summary="Get user", description="Observed user lookup")
    original_response = deepcopy(document["responses"]["200"])
    spec = generate_openapi([document], tmp_path)
    operation = spec["paths"]["/users/{value}"]["get"]

    assert operation["summary"] == "Get user"
    assert operation["description"] == "Observed user lookup"
    response = operation["responses"]["200"]
    assert response["description"] == "Observed HTTP 200"
    media = response["content"][original_response["contentType"]]
    assert media["schema"] == original_response["bodySchema"]
    assert media["example"] == original_response["example"]


@pytest.mark.parametrize("example", [{}, [], 0, False, ""])
def test_observed_falsey_json_bodies_are_preserved(
    tmp_path: Path, example: Any
) -> None:
    schema = {"type": "object", "properties": {}} if example == {} else {}
    spec = generate_openapi(
        [
            interface(
                method="POST",
                body_observed=True,
                example=example,
                body_schema=schema,
            )
        ],
        tmp_path,
    )
    media = spec["paths"]["/users/{value}"]["post"]["requestBody"]["content"][
        "application/json"
    ]
    assert media["example"] == example
    assert media["schema"] == schema


def test_unobserved_get_body_is_not_inferred_from_schema(tmp_path: Path) -> None:
    spec = generate_openapi(
        [interface(method="GET", body_observed=False, example=None)], tmp_path
    )
    operation = spec["paths"]["/users/{value}"]["get"]
    assert "requestBody" not in operation


def test_legacy_body_fallback_and_json_yaml_round_trip(tmp_path: Path) -> None:
    # Legacy documents have no bodyObserved marker. A non-None example is the
    # only reliable evidence; this retains an actually observed empty object.
    legacy_with_body = interface(method="POST", body_observed=None, example={})
    legacy_without_body = interface(
        path="/favicon.ico", method="GET", body_observed=None, example=None
    )
    returned = generate_openapi([legacy_with_body, legacy_without_body], tmp_path)

    assert "requestBody" in returned["paths"]["/users/{value}"]["post"]
    assert "requestBody" not in returned["paths"]["/favicon.ico"]["get"]
    from_json = json.loads((tmp_path / "openapi.json").read_text(encoding="utf-8"))
    from_yaml = yaml.safe_load((tmp_path / "openapi.yaml").read_text(encoding="utf-8"))
    assert from_json == returned
    assert from_yaml == returned


@pytest.mark.skipif(
    validate_spec is None,
    reason="openapi-spec-validator is unavailable in this environment",
)
def test_generated_json_and_yaml_validate_as_openapi_31(tmp_path: Path) -> None:
    generate_openapi(
        [
            interface(),
            interface(
                path="/teams/{teamId}/members/{memberId}",
                method="POST",
                body_observed=True,
                example={},
            ),
        ],
        tmp_path,
    )
    from_json = json.loads((tmp_path / "openapi.json").read_text(encoding="utf-8"))
    from_yaml = yaml.safe_load((tmp_path / "openapi.yaml").read_text(encoding="utf-8"))
    validate_spec(from_json)
    validate_spec(from_yaml)
