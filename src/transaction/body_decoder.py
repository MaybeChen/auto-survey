from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Any
@dataclass
class DecodeResult: body: Any | None; parse_error: str | None=None
def is_json_type(content_type:str|None)->bool:
    media=(content_type or "").split(";",1)[0].strip().lower()
    return media in {"application/json","text/json"} or (media.startswith("application/") and media.endswith("+json"))
def decode_body(raw:str|None,content_type:str|None,content_encoding:str|None=None)->DecodeResult:
    if not raw: return DecodeResult(None)
    try:
        compact=raw.replace(":","").replace(" ","")
        data=bytes.fromhex(compact)
    except ValueError: data=raw.encode()
    charset="utf-8"
    if content_type and "charset=" in content_type.lower(): charset=content_type.lower().split("charset=",1)[1].split(";",1)[0].strip()
    try: text=data.decode(charset)
    except (LookupError,UnicodeDecodeError): text=data.decode("utf-8",errors="replace")
    if is_json_type(content_type):
        try: return DecodeResult(json.loads(text))
        except json.JSONDecodeError as exc: return DecodeResult({"_raw":text},f"invalid JSON: {exc.msg}")
    return DecodeResult(text)
