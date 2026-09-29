from collections import defaultdict
from dataclasses import dataclass, field
from src.models import Transaction
from .normalizer import normalize_path
@dataclass
class EndpointGroup:
    host:str; method:str; normalized_path:str; samples:list[Transaction]=field(default_factory=list)
    @property
    def key(self)->tuple[str,str,str]: return self.host,self.method,self.normalized_path
    @property
    def observed_paths(self)->list[str]: return sorted({x.request.path for x in self.samples})
def group_transactions(transactions:list[Transaction],max_samples:int=20)->list[EndpointGroup]:
    groups:dict[tuple[str,str,str],EndpointGroup]={}
    for tx in transactions:
        key=(tx.request.host or tx.request.dst_ip or "unknown",tx.request.method.upper(),normalize_path(tx.request.path))
        group=groups.setdefault(key,EndpointGroup(*key))
        if len(group.samples)<max_samples: group.samples.append(tx)
    return sorted(groups.values(),key=lambda x:x.key)
