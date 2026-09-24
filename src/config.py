"""YAML configuration and portable storage layout."""
from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml
from pydantic import BaseModel, Field

HEADERS=["authorization","cookie","set-cookie","proxy-authorization","x-api-key"]
FIELDS=["password","passwd","pwd","token","accessToken","access_token","refreshToken","refresh_token","secret","apiKey","api_key","mobile","phone","idCard","id_card"]
class StorageConfig(BaseModel): root: Path=Path("./data")
class CaptureConfig(BaseModel):
    backend: str="dumpcap"; interface: str=""; filter: str=""; stable_seconds: int=20
    duration_seconds: int=300; filesize_kb: int=51200; files: int=288
class ToolConfig(BaseModel): path: Path | None=None
class AnalysisConfig(BaseModel): min_samples: int=3; max_samples_per_endpoint: int=20; publish_confidence: float=.85
class RedactionConfig(BaseModel): headers: list[str]=Field(default_factory=lambda:list(HEADERS)); json_fields: list[str]=Field(default_factory=lambda:list(FIELDS)); replacement: str="***"
class AIConfig(BaseModel): enabled: bool=False; provider: str=""; model: str=""; base_url: str=""; api_key_env: str="AI_API_KEY"; retries: int=2
class DatabaseConfig(BaseModel): enabled: bool=False; url: str=""
class OutputConfig(BaseModel): generate_json: bool=True; generate_openapi: bool=True
class AppConfig(BaseModel):
    storage: StorageConfig=Field(default_factory=StorageConfig); capture: CaptureConfig=Field(default_factory=CaptureConfig)
    tshark: ToolConfig=Field(default_factory=ToolConfig); dumpcap: ToolConfig=Field(default_factory=ToolConfig)
    analysis: AnalysisConfig=Field(default_factory=AnalysisConfig); redaction: RedactionConfig=Field(default_factory=RedactionConfig)
    ai: AIConfig=Field(default_factory=AIConfig); database: DatabaseConfig=Field(default_factory=DatabaseConfig)
    output: OutputConfig=Field(default_factory=OutputConfig)
    def create_directories(self)->dict[str,Path]:
        root=self.storage.root.expanduser()
        paths={"incoming":root/"capture"/"incoming","raw":root/"work"/"raw","transactions":root/"work"/"transactions","redacted":root/"work"/"redacted","state":root/"state","interfaces":root/"output"/"interfaces","openapi":root/"output"/"openapi","reports":root/"output"/"reports","samples":root/"output"/"samples"}
        for path in paths.values(): path.mkdir(parents=True,exist_ok=True)
        return paths

def load_config(path: Path | None=None)->AppConfig:
    data: dict[str,Any]={}
    if path:
        data=yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    config=AppConfig.model_validate(data); config.create_directories(); return config
