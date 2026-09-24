from __future__ import annotations
from collections import defaultdict
from typing import Any
def json_type(v:Any)->str:
    if v is None:return "null"
    if isinstance(v,bool):return "boolean"
    if isinstance(v,int):return "integer"
    if isinstance(v,float):return "number"
    if isinstance(v,str):return "string"
    if isinstance(v,list):return "array"
    return "object"
def observe_fields(samples:list[Any])->dict[str,Any]:
    total=len(samples); seen=defaultdict(int); types=defaultdict(set); examples=defaultdict(list); arrays=defaultdict(set); children=defaultdict(list)
    for sample in samples:
        if not isinstance(sample,dict): continue
        for key,value in sample.items():
            seen[key]+=1; types[key].add(json_type(value))
            if value not in examples[key] and len(examples[key])<3: examples[key].append(value)
            if isinstance(value,list): arrays[key].update(json_type(x) for x in value)
            if isinstance(value,dict): children[key].append(value)
    return {key:{"field":key,"count":seen[key],"sampleCount":total,"observedPresence":seen[key]/total if total else 0,"observedTypes":sorted(types[key]),"nullable":"null" in types[key],"examples":examples[key],"arrayElementTypes":sorted(arrays[key]),"childFields":observe_fields(children[key])} for key in sorted(seen)}
def infer_schema(value:Any)->dict[str,Any]:
    kind=json_type(value)
    if kind=="object": return {"type":"object","properties":{k:infer_schema(v) for k,v in value.items()}}
    if kind=="array": return {"type":"array","items":infer_schema(value[0]) if value else {}}
    return {"type":kind}
