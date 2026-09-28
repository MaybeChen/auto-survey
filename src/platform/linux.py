from pathlib import Path
import shutil, subprocess
from .base import PlatformAdapter
class LinuxPlatformAdapter(PlatformAdapter):
    def _find(self,name:str)->Path:
        found=shutil.which(name)
        if not found: raise FileNotFoundError(f"{name} not found; install the Wireshark CLI package and configure capture permissions")
        return Path(found)
    def find_tshark(self)->Path: return self._find("tshark")
    def find_dumpcap(self)->Path: return self._find("dumpcap")
    def find_tcpdump(self)->Path: return self._find("tcpdump")
    def list_interfaces(self)->list[dict[str,str]]:
        result=subprocess.run([str(self.find_dumpcap()),"-D"],shell=False,check=True,capture_output=True,text=True,timeout=10)
        return [{"index":x.split(".",1)[0],"name":x.split(".",1)[1].strip()} for x in result.stdout.splitlines() if "." in x]
    def validate_capture_permissions(self)->bool:
        try: subprocess.run([str(self.find_dumpcap()),"-D"],shell=False,check=True,capture_output=True,timeout=10); return True
        except (OSError,subprocess.SubprocessError): return False
