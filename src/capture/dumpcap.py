from pathlib import Path
from .base import CaptureBackend
class DumpcapBackend(CaptureBackend):
    def __init__(self,executable:Path,interface:str,filter_:str="",duration:int=300,filesize_kb:int=51200,files:int=288):
        self.executable=executable; self.interface=interface; self.filter=filter_; self.duration=duration; self.filesize_kb=filesize_kb; self.files=files
    def build_command(self,output:Path)->list[str]:
        args=[str(self.executable),"-i",self.interface]
        if self.filter: args += ["-f",self.filter]
        return args+["-s","0","-B","64","-b",f"duration:{self.duration}","-b",f"filesize:{self.filesize_kb}","-b",f"files:{self.files}","-w",str(output)]
