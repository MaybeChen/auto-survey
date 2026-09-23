import platform
from .base import PlatformAdapter
from .linux import LinuxPlatformAdapter
from .windows import WindowsPlatformAdapter
def get_platform_adapter(system:str|None=None)->PlatformAdapter:
    name=system or platform.system()
    if name=="Windows": return WindowsPlatformAdapter()
    if name=="Linux": return LinuxPlatformAdapter()
    raise RuntimeError(f"Unsupported platform: {name}")
