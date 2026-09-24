import re
from urllib.parse import unquote
UUID=re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",re.I)
DATE=re.compile(r"^\d{4}-\d{2}-\d{2}$")
HEX=re.compile(r"^(?:[0-9a-f]{16,}|[0-9a-f]{8,}-[0-9a-f-]+)$",re.I)
INTEGER=re.compile(r"^-?\d+$")
def normalize_path(path:str)->str:
    clean=unquote(path.split("?",1)[0]) or "/"; parts=[]
    for part in clean.split("/"):
        dynamic=bool(UUID.match(part) or DATE.match(part) or HEX.match(part) or INTEGER.match(part))
        parts.append("{value}" if dynamic else part)
    return "/".join(parts) or "/"
def path_matches(normalized:str,observed:str)->bool:
    """Match observed segments against generic or AI-named placeholders."""
    expected=[] if normalized=="/" else normalized.strip("/").split("/")
    actual=[] if observed=="/" else observed.strip("/").split("/")
    return len(expected)==len(actual) and all(
        (left.startswith("{") and left.endswith("}")) or left==right
        for left,right in zip(expected,actual)
    )
