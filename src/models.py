"""Validated domain models shared by the deterministic pipeline and AI boundary."""
from __future__ import annotations
from enum import StrEnum
from typing import Any
from pydantic import BaseModel, Field

class CaptureStatus(StrEnum):
    DISCOVERED="DISCOVERED"; STABLE="STABLE"; PROBING="PROBING"; PARSING="PARSING"
    PARSED="PARSED"; ANALYZING="ANALYZING"; PENDING_MORE_SAMPLES="PENDING_MORE_SAMPLES"
    DONE="DONE"; FAILED="FAILED"; BLOCKED_TLS="BLOCKED_TLS"

class HTTPRequest(BaseModel):
    frame: int; timestamp: float | None=None; src_ip: str | None=None; src_port: int | None=None
    dst_ip: str | None=None; dst_port: int | None=None; method: str; host: str | None=None
    path: str; full_uri: str | None=None; query: dict[str, Any]=Field(default_factory=dict)
    headers: dict[str, Any]=Field(default_factory=dict); content_type: str | None=None; body: Any | None=None
    parse_error: str | None=None

class HTTPResponse(BaseModel):
    frame: int; status: int | None=None; content_type: str | None=None
    headers: dict[str, Any]=Field(default_factory=dict); body: Any | None=None; parse_error: str | None=None

class Transaction(BaseModel):
    id: str; protocol: str="http/1.1"; tcp_stream: int | None=None
    request: HTTPRequest; response: HTTPResponse | None=None

class EndpointAnalysisRequest(BaseModel):
    host: str; method: str; normalized_path: str; samples: list[Transaction]
    observations: dict[str, Any]=Field(default_factory=dict)

class EndpointAnalysisResult(BaseModel):
    summary: str | None=None; description: str | None=None; normalized_path: str
    request_schema: dict[str, Any]=Field(default_factory=dict); responses: dict[str, Any]=Field(default_factory=dict)
    field_descriptions: dict[str, str]=Field(default_factory=dict); confidence: float=Field(ge=0, le=1)
    uncertain: list[str]=Field(default_factory=list)
