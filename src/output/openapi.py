from pathlib import Path
import json,yaml
from typing import Any
def generate_openapi(interfaces:list[dict[str,Any]],output_dir:Path)->dict[str,Any]:
    servers=sorted({f"http://{x['host']}" for x in interfaces}); paths={}
    for item in interfaces:
        operation={"summary":item.get("summary"),"description":item.get("description"),"responses":{}}
        body=item["request"].get("bodySchema")
        if body: operation["requestBody"]={"content":{item["request"].get("contentType") or "application/json":{"schema":body,"example":item["request"].get("example")}}}
        for status,response in item["responses"].items(): operation["responses"][status]={"description":f"Observed HTTP {status}","content":{response.get("contentType") or "application/json":{"schema":response.get("bodySchema",{}),"example":response.get("example")}}}
        paths.setdefault(item["path"],{})[item["method"].lower()]=operation
    spec={"openapi":"3.1.0","info":{"title":"Observed API Catalog","version":"1.0.0"},"servers":[{"url":x} for x in servers],"paths":paths}
    output_dir.mkdir(parents=True,exist_ok=True); (output_dir/"openapi.json").write_text(json.dumps(spec,indent=2,ensure_ascii=False)+"\n",encoding="utf-8"); (output_dir/"openapi.yaml").write_text(yaml.safe_dump(spec,sort_keys=False,allow_unicode=True),encoding="utf-8"); return spec
def load_interfaces(directory:Path)->list[dict[str,Any]]: return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.json"))]
