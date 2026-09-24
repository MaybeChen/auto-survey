from abc import ABC, abstractmethod
from pathlib import Path
import subprocess
class CaptureBackend(ABC):
    @abstractmethod
    def build_command(self, output:Path)->list[str]: ...
    def start(self,output:Path)->subprocess.Popen[bytes]:
        output.parent.mkdir(parents=True,exist_ok=True)
        return subprocess.Popen(self.build_command(output),shell=False,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
