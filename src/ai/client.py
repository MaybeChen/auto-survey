"""Vendor-neutral OpenAI-compatible structured JSON transport."""
import json,os
import httpx
from src.models import EndpointAnalysisRequest,EndpointAnalysisResult
from .base import AIClient
class HTTPAIClient(AIClient):
    def __init__(self,base_url:str,model:str,api_key_env:str="AI_API_KEY",retries:int=2): self.base_url=base_url.rstrip("/"); self.model=model; self.api_key_env=api_key_env; self.retries=retries
    def analyze_endpoint(self,request:EndpointAnalysisRequest)->EndpointAnalysisResult:
        key=os.environ.get(self.api_key_env)
        if not key: raise RuntimeError(f"AI API key environment variable {self.api_key_env} is not set")
        payload=request.model_dump(mode="json")
        # This boundary receives redacted samples only; it has no filesystem API.
        messages=[{"role":"system","content":"Infer an API schema only from evidence. Return JSON matching EndpointAnalysisResult; never invent fields."},{"role":"user","content":json.dumps(payload,ensure_ascii=False)}]
        error:Exception|None=None
        for _ in range(self.retries+1):
            try:
                response=httpx.post(f"{self.base_url}/chat/completions",headers={"Authorization":f"Bearer {key}"},json={"model":self.model,"messages":messages,"response_format":{"type":"json_object"}},timeout=60); response.raise_for_status()
                return EndpointAnalysisResult.model_validate_json(response.json()["choices"][0]["message"]["content"])
            except (httpx.HTTPError,KeyError,ValueError) as exc:error=exc
        raise RuntimeError("FAILED_AI_PARSE") from error
