from pathlib import Path
import time
class CaptureScanner:
    def __init__(self,incoming:Path,stable_seconds:int=20): self.incoming=incoming; self.stable_seconds=stable_seconds; self._sizes:dict[Path,int]={}
    def scan(self)->list[Path]:
        now=time.time(); stable=[]
        for path in sorted((*self.incoming.glob("*.pcap"),*self.incoming.glob("*.pcapng"))):
            stat=path.stat(); previous=self._sizes.get(path); self._sizes[path]=stat.st_size
            if now-stat.st_mtime>=self.stable_seconds and previous==stat.st_size: stable.append(path)
        return stable
