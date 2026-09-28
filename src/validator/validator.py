from __future__ import annotations
from typing import Any
from src.endpoint.cluster import EndpointGroup
from src.endpoint.normalizer import path_matches
from src.models import EndpointAnalysisResult

def _properties(schema:dict[str,Any])->set[str]: return set(schema.get("properties",{}))
def validate_analysis(group:EndpointGroup,result:EndpointAnalysisResult)->dict[str,Any]:
    issues=[]
    if any(not path_matches(result.normalized_path,p) for p in group.observed_paths): issues.append("normalized path does not cover every observed path")
    statuses={str(x.response.status) for x in group.samples if x.response and x.response.status is not None}
    invented_status=set(result.responses)-statuses
    if invented_status: issues.append(f"unobserved response statuses: {sorted(invented_status)}")
    request_fields=set().union(*(set(x.request.body) for x in group.samples if isinstance(x.request.body,dict)))
    invented=_properties(result.request_schema)-request_fields
    if invented: issues.append(f"unobserved request fields: {sorted(invented)}")
    for status,data in result.responses.items():
        observed=[x.response.body for x in group.samples if x.response and str(x.response.status)==status and isinstance(x.response.body,dict)]
        actual=set().union(*(set(x) for x in observed)) if observed else set()
        schema=data.get("bodySchema",data) if isinstance(data,dict) else {}
        extra=_properties(schema)-actual
        if extra: issues.append(f"unobserved response fields for {status}: {sorted(extra)}")
        example=data.get("example") if isinstance(data,dict) else None
        if example is not None and example not in observed: issues.append(f"response example for {status} is not observed")
    confidence=max(0.0,min(result.confidence,1.0-len(issues)*.2))
    return {"confidence":confidence,"issues":issues,"evidence":{"sampleCount":len(group.samples),"observedPaths":group.observed_paths,"observedStatusCodes":sorted(statuses)}}
