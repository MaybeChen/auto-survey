from pathlib import Path
from .runner import TsharkRunner
PROTOCOLS=("tcp","http","tls","http2","quic")
def parse_protocol_lines(output:str)->dict[str,int]:
    counts={key:0 for key in PROTOCOLS}
    for line in output.splitlines():
        found=set(line.lower().split(":"))
        for protocol in counts:
            if protocol in found: counts[protocol]+=1
    return counts
def probe_protocols(runner:TsharkRunner,pcap:Path)->dict[str,int]:
    return parse_protocol_lines(runner.run(["-r",str(pcap),"-T","fields","-e","frame.protocols"]))
