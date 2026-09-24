"""Safe, bounded tshark subprocess wrapper."""
from pathlib import Path
import subprocess
class TsharkError(RuntimeError): pass
class TsharkRunner:
    def __init__(self,executable:Path,timeout:int=120,max_output_bytes:int=100_000_000): self.executable=executable; self.timeout=timeout; self.max_output_bytes=max_output_bytes
    def run(self,args:list[str])->str:
        if not self.executable.exists(): raise FileNotFoundError(f"tshark not found: {self.executable}")
        try: result=subprocess.run([str(self.executable),*args],shell=False,capture_output=True,timeout=self.timeout,check=False)
        except subprocess.TimeoutExpired as exc: raise TsharkError(f"tshark timed out after {self.timeout}s") from exc
        if result.returncode: raise TsharkError(f"tshark failed ({result.returncode}): {result.stderr.decode(errors='replace')[:2000]}")
        if len(result.stdout)>self.max_output_bytes: raise TsharkError("tshark output exceeds configured limit")
        return result.stdout.decode("utf-8",errors="replace")
