from datetime import datetime,timezone
from pathlib import Path
import json
from typing import Any
def write_catalog(output_root:Path,documents:list[tuple[Path,dict[str,Any]]])->Path:
    entries=[{"host":d["host"],"method":d["method"],"path":d["path"],"file":f"interfaces/{p.name}","sampleCount":d["statistics"]["sampleCount"],"confidence":d["confidence"]} for p,d in documents]
    result={"generatedAt":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"endpointCount":len(entries),"endpoints":entries}; path=output_root/"api-catalog.json"; path.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8"); return path
