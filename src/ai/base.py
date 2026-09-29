from abc import ABC, abstractmethod
from src.models import EndpointAnalysisRequest,EndpointAnalysisResult
class AIClient(ABC):
    @abstractmethod
    def analyze_endpoint(self,request:EndpointAnalysisRequest)->EndpointAnalysisResult: ...
