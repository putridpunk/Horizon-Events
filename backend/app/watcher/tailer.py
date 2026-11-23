"""Incremental reading of a growing log file. Pure Python, no database."""
from __future__ import annotations

from pathlib import Path

_CHUNK = 65_536


class FileTailer:
    """Returns only complete lines (ending in a newline) added since the last call.

    A half-written last line is left for the next call. If the file becomes smaller than the
    remembered offset (truncated or replaced), reading restarts from the beginning. A file
    replaced by a larger one cannot be told apart from an append; the event fingerprint
    prevents duplicates in that case.
    """

    def __init__(self) -> None:
        self.offset = 0

    def read_new(self, path: Path, max_bytes: int = 1_048_576) -> bytes:
        try:
            size = path.stat().st_size
        except OSError:
            return b""
        if size < self.offset:
            self.offset = 0
        if size == self.offset:
            return b""
        try:
            with open(path, "rb") as f:
                f.seek(self.offset)
                data = f.read(max_bytes)
                cut = data.rfind(b"\n")
                if cut != -1:
                    data = data[:cut + 1]
                elif len(data) < max_bytes:
                    return b""  # a partial line: wait for its newline
                else:  # one line longer than the cap: read it whole
                    buf = bytearray(data)
                    while True:
                        chunk = f.read(_CHUNK)
                        if not chunk:
                            return b""
                        i = chunk.find(b"\n")
                        if i != -1:
                            buf += chunk[:i + 1]
                            break
                        buf += chunk
                    data = bytes(buf)
        except OSError:
            return b""
        self.offset += len(data)
        return data
