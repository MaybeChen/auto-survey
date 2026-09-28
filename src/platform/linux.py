from pathlib import Path
import shutil, subprocess
from .base import PlatformAdapter
from .interfaces import list_dumpcap_interfaces
class LinuxPlatformAdapter(PlatformAdapter):
    def _find(self,name:str)->Path:
        found=shutil.which(name)
        if not found: raise FileNotFoundError(f"{name} not found; install the Wireshark CLI package and configure capture permissions")
        return Path(found)
    def find_tshark(self)->Path: return self._find("tshark")
    def find_dumpcap(self)->Path: return self._find("dumpcap")
    def find_tcpdump(self)->Path: return self._find("tcpdump")
    def list_interfaces(self)->list[dict[str,str]]:
        return list_dumpcap_interfaces(self.find_dumpcap())
    def validate_capture_permissions(self)->bool:
        try: list_dumpcap_interfaces(self.find_dumpcap()); return True
        except (OSError,subprocess.SubprocessError,RuntimeError): return False
