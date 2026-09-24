from pathlib import Path
import time


class CaptureScanner:
    """Yield stable captures once per process, without requiring a database."""

    def __init__(self, incoming: Path, stable_seconds: int = 20):
        self.incoming = incoming
        self.stable_seconds = stable_seconds
        self._sizes: dict[Path, int] = {}
        self._emitted: set[tuple[Path, int, int]] = set()

    def scan(self) -> list[Path]:
        now = time.time()
        stable: list[Path] = []
        for path in sorted((*self.incoming.glob("*.pcap"), *self.incoming.glob("*.pcapng"))):
            stat = path.stat()
            previous = self._sizes.get(path)
            self._sizes[path] = stat.st_size
            identity = (path, stat.st_mtime_ns, stat.st_size)
            if (
                now - stat.st_mtime >= self.stable_seconds
                and previous == stat.st_size
                and identity not in self._emitted
            ):
                stable.append(path)
                self._emitted.add(identity)
        return stable
