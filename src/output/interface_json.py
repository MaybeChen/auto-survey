from __future__ import annotations
from pathlib import Path
import json,re
from typing import Any
from src.endpoint.cluster import EndpointGroup
from src.models import EndpointAnalysisResult
def filename(method:str,path:str)->str:
    stem=re.sub(r"[^A-Za-z0-9]+","_",path.replace("{value}","value")).strip("_") or "root"
    return f"{method.upper()}_{stem}.json"
def build_interface(group:EndpointGroup,result:EndpointAnalysisResult,validation:dict[str,Any])->dict[str,Any]:
    request_example=next((x.request.body for x in group.samples if x.request.body is not None),None); statuses={}
    for tx in group.samples:
        if tx.response and tx.response.status is not None:
            key=str(tx.response.status); ai=result.responses.get(key,{})
            statuses.setdefault(key,{"contentType":tx.response.content_type,"bodySchema":ai.get("bodySchema",ai) if isinstance(ai,dict) else {},"example":tx.response.body})
    success=sum(1 for x in group.samples if x.response and x.response.status and x.response.status<400)
    return {"service":None,"host":group.host,"method":group.method,"path":result.normalized_path,"summary":result.summary,"description":result.description,"request":{"contentType":group.samples[0].request.content_type,"query":group.samples[0].request.query,"headers":{},"bodyObserved":any(x.request.body is not None for x in group.samples),"bodySchema":result.request_schema,"example":request_example},"responses":statuses,"statistics":{"sampleCount":len(group.samples),"successCount":success,"errorCount":len(group.samples)-success},"evidence":{"observedPaths":group.observed_paths,"observedStatusCodes":validation["evidence"]["observedStatusCodes"]},"confidence":validation["confidence"],"unknown":result.uncertain+validation["issues"]}
def write_interface(output_dir:Path,document:dict[str,Any])->Path:
    output_dir.mkdir(parents=True,exist_ok=True); path=output_dir/filename(document["method"],document["path"]); path.write_text(json.dumps(document,indent=2,ensure_ascii=False)+"\n",encoding="utf-8"); return path
