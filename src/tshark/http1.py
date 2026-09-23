from pathlib import Path
import json
from typing import Any
from .runner import TsharkRunner
FIELDS=["frame.number","frame.time_epoch","ip.src","ip.dst","tcp.srcport","tcp.dstport","tcp.stream","http.request.method","http.host","http.request.uri","http.request.full_uri","http.request.uri.query","http.response.code","http.content_type","http.content_encoding","http.content_length","http.request_in","http.response_in","http.authorization","http.cookie","http.set_cookie","http.body.reassembled.data","http.file_data"]
def build_http1_args(pcap:Path)->list[str]:
    args=["-2","-r",str(pcap),"-Y","http.request or http.response","-T","json"]
    for field in FIELDS: args += ["-e",field]
    return args
def extract_http1(runner:TsharkRunner,pcap:Path)->list[dict[str,Any]]:
    value=json.loads(runner.run(build_http1_args(pcap)))
    if not isinstance(value,list): raise ValueError("unexpected tshark JSON")
    return value

def flatten_packet(packet:dict[str,Any])->dict[str,Any]:
    layers=packet.get("_source",{}).get("layers",{})
    return {key:(value[0] if isinstance(value,list) and value else value) for key,value in layers.items()}
