from pathlib import Path
import shutil, subprocess
from .base import PlatformAdapter
class WindowsPlatformAdapter(PlatformAdapter):
    def _find(self,name:str)->Path:
        found=shutil.which(name) or shutil.which(f"{name}.exe")
        candidate=Path("C:/Program Files/Wireshark")/f"{name}.exe"
        if found: return Path(found)
        if candidate.exists(): return candidate
        raise FileNotFoundError(f"{name}.exe not found; install Wireshark and Npcap or add it to PATH")
    def find_tshark(self)->Path: return self._find("tshark")
    def find_dumpcap(self)->Path: return self._find("dumpcap")
    def list_interfaces(self)->list[dict[str,str]]: return _interfaces(self.find_dumpcap())
    def validate_capture_permissions(self)->bool:
        try: subprocess.run([str(self.find_dumpcap()),"-D"],shell=False,check=True,capture_output=True,timeout=10); return True
        except (OSError,subprocess.SubprocessError): return False

def _interfaces(tool:Path)->list[dict[str,str]]:
    result=subprocess.run([str(tool),"-D"],shell=False,check=True,capture_output=True,text=True,timeout=10)
    return [{"index":line.split(".",1)[0],"name":line.split(".",1)[1].strip()} for line in result.stdout.splitlines() if "." in line]
