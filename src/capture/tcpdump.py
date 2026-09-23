from pathlib import Path
from .base import CaptureBackend
class TcpdumpBackend(CaptureBackend):
    def __init__(self,executable:Path,interface:str,filter_:str=""): self.executable=executable; self.interface=interface; self.filter=filter_
    def build_command(self,output:Path)->list[str]:
        args=[str(self.executable),"-i",self.interface,"-s","0","-w",str(output)]
        if self.filter: args.append(self.filter)
        return args
