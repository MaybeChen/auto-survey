from __future__ import annotations
from collections import defaultdict, deque
from hashlib import sha256
from typing import Any
from urllib.parse import parse_qs, urlsplit
from src.models import HTTPRequest, HTTPResponse, Transaction
from src.tshark.http1 import flatten_packet
from .body_decoder import decode_body

def _v(row:dict[str,Any],key:str)->Any: return row.get(key)
def build_transactions(packets:list[dict[str,Any]])->list[Transaction]:
    rows=sorted((flatten_packet(p) for p in packets),key=lambda x:int(_v(x,"frame.number") or 0))
    requests:dict[int,tuple[HTTPRequest,int|None]]={}; responses:dict[int,HTTPResponse]={}; expected_response:dict[int,int]={}; pending:dict[int|None,deque[int]]=defaultdict(deque)
    for row in rows:
        frame=int(_v(row,"frame.number")); stream=int(_v(row,"tcp.stream")) if _v(row,"tcp.stream") is not None else None
        if _v(row,"http.request.method"):
            uri=str(_v(row,"http.request.uri") or "/"); split=urlsplit(uri); content_type=_v(row,"http.content_type")
            decoded=decode_body(_v(row,"http.body.reassembled.data") or _v(row,"http.file_data"),content_type,_v(row,"http.content_encoding"))
            headers={k:v for k,v in {"authorization":_v(row,"http.authorization"),"cookie":_v(row,"http.cookie")}.items() if v is not None}
            req=HTTPRequest(frame=frame,timestamp=float(_v(row,"frame.time_epoch")) if _v(row,"frame.time_epoch") else None,src_ip=_v(row,"ip.src"),src_port=int(_v(row,"tcp.srcport")) if _v(row,"tcp.srcport") else None,dst_ip=_v(row,"ip.dst"),dst_port=int(_v(row,"tcp.dstport")) if _v(row,"tcp.dstport") else None,method=str(_v(row,"http.request.method")),host=_v(row,"http.host"),path=split.path or "/",full_uri=_v(row,"http.request.full_uri"),query={k:v if len(v)>1 else v[0] for k,v in parse_qs(split.query,keep_blank_values=True).items()},headers=headers,content_type=content_type,body=decoded.body,parse_error=decoded.parse_error)
            requests[frame]=(req,stream); pending[stream].append(frame)
            if _v(row,"http.response_in"): expected_response[int(_v(row,"http.response_in"))]=frame
        elif _v(row,"http.response.code"):
            content_type=_v(row,"http.content_type"); decoded=decode_body(_v(row,"http.body.reassembled.data") or _v(row,"http.file_data"),content_type,_v(row,"http.content_encoding"))
            response=HTTPResponse(frame=frame,status=int(_v(row,"http.response.code")),content_type=content_type,headers={"set-cookie":_v(row,"http.set_cookie")} if _v(row,"http.set_cookie") else {},body=decoded.body,parse_error=decoded.parse_error)
            request_in=_v(row,"http.request_in")
            target=int(request_in) if request_in else expected_response.get(frame)
            if target is None: target=pending[stream].popleft() if pending[stream] else None
            elif target in pending[stream]: pending[stream].remove(target)
            if target is not None: responses[target]=response
    result=[]
    for frame,(request,stream) in requests.items():
        response=responses.get(frame); ident=sha256(f"{stream}:{frame}:{request.method}:{request.path}".encode()).hexdigest()[:24]
        result.append(Transaction(id=ident,tcp_stream=stream,request=request,response=response))
    return result
