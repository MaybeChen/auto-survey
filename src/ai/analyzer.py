from src.endpoint.cluster import EndpointGroup
from src.endpoint.samples import infer_schema,observe_fields
from src.models import EndpointAnalysisRequest,EndpointAnalysisResult
from .base import AIClient
def deterministic_analysis(group:EndpointGroup)->EndpointAnalysisResult:
    req=next((x.request.body for x in group.samples if x.request.body is not None),{})
    responses={}
    for tx in group.samples:
        if tx.response and tx.response.status is not None: responses.setdefault(str(tx.response.status),{"bodySchema":infer_schema(tx.response.body),"example":tx.response.body})
    return EndpointAnalysisResult(summary=None,normalized_path=group.normalized_path,request_schema=infer_schema(req),responses=responses,confidence=1.0 if group.samples else 0,uncertain=["Semantic descriptions require configured AI"])
def analyze(group:EndpointGroup,client:AIClient|None)->EndpointAnalysisResult:
    if client is None:return deterministic_analysis(group)
    request=EndpointAnalysisRequest(host=group.host,method=group.method,normalized_path=group.normalized_path,samples=group.samples,observations=observe_fields([x.request.body for x in group.samples]))
    return client.analyze_endpoint(request)
