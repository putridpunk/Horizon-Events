"""Receive syslog over the network (UDP and TCP) and feed it into the normal import path.

Off unless HORIZON_SYSLOG_PORT is set. It listens on 127.0.0.1 unless HORIZON_SYSLOG_BIND says otherwise. Syslog has no
login, so anything that can reach the port can add events: expose it only to networks you trust."""
from __future__ import annotations

import logging
import re
import socket
import threading
from collections import deque
from datetime import datetime
from typing import Callable

from sqlalchemy.orm import Session

from app.domain import utcnow
from app.services.ingestion import import_logs
from app.syslog import lines as syslog_lines

log = logging.getLogger(__name__)

MAX_QUEUE = 20_000
MAX_BATCH = 2_000
MAX_CONNECTIONS = 32
IDLE_TIMEOUT = 300.0
_OCTET_COUNT = re.compile(rb"^(\d{1,5}) ")


class SyslogReceiver:
    def __init__(self, session_factory: Callable[[], Session], bind: str = "127.0.0.1", port: int = 5514,
                 flush_interval: float = 2.0, now: Callable[[], datetime] = utcnow):
        self.session_factory, self.bind, self.port = session_factory, bind, port
        self.flush_interval, self.now = flush_interval, now
        self._queue: deque[str] = deque()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self._connections = 0
        self.stats = {"received": 0, "dropped": 0, "ignored": 0, "imported": 0, "alerts": 0, "last_message": None,
                      "last_error": None, "tcp_connections": 0}

    # ---- intake --------------------------------------------------------------------------------------------------
    def feed(self, data: bytes | str, sender: str | None = None) -> bool:
        """Accept one message. Returns False if it was empty."""
        line = syslog_lines.parse_datagram(data, self.now(), sender)
        with self._lock:
            if line is None:
                self.stats["ignored"] += 1
                return False
            if len(self._queue) >= MAX_QUEUE:
                self._queue.popleft()  # keep the newest: during a flood the oldest are the least useful
                self.stats["dropped"] += 1
            self._queue.append(line)
            self.stats["received"] += 1
            self.stats["last_message"] = self.now().isoformat()
        return True

    # ---- flushing ------------------------------------------------------------------------------------------------
    def flush(self) -> int:
        """Import everything queued. Returns how many events were stored."""
        total = 0
        while True:
            with self._lock:
                batch = [self._queue.popleft() for _ in range(min(MAX_BATCH, len(self._queue)))]
            if not batch:
                return total
            for source_type, content in syslog_lines.route(batch).items():
                try:
                    with self.session_factory() as session:
                        result = import_logs(session, source_type, f"syslog:{self.port}", content, self.now())
                    total += result["imported"]
                    with self._lock:
                        self.stats["imported"] += result["imported"]
                        self.stats["alerts"] += result["alerts_created"]
                        self.stats["last_error"] = None
                except Exception as exc:  # a bad batch must not stop the receiver
                    log.exception("importing syslog messages failed")
                    with self._lock:
                        self.stats["last_error"] = f"{type(exc).__name__}: {exc}"[:300]

    # ---- sockets -------------------------------------------------------------------------------------------------
    def start(self, udp: bool = True, tcp: bool = True) -> None:
        if udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.bind, self.port))
            self.port = sock.getsockname()[1]
            self._spawn(self._udp_loop, sock)
        if tcp:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.bind, self.port))
            server.listen(16)
            self.port = server.getsockname()[1]
            self._spawn(self._accept_loop, server)
        self._spawn(self._flush_loop, None)

    def _spawn(self, target, sock) -> None:
        if sock is not None:
            sock.settimeout(0.5)
            self._sockets.append(sock)
        thread = threading.Thread(target=target, args=(sock,) if sock is not None else (), daemon=True,
                                  name=f"syslog-{target.__name__}")
        thread.start()
        self._threads.append(thread)

    def _udp_loop(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self.feed(data, addr[0])

    def _accept_loop(self, server: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                if self._connections >= MAX_CONNECTIONS:
                    conn.close()
                    continue
                self._connections += 1
                self.stats["tcp_connections"] = self._connections
            threading.Thread(target=self._serve, args=(conn, addr[0]), daemon=True, name="syslog-conn").start()

    def _serve(self, conn: socket.socket, sender: str) -> None:
        conn.settimeout(IDLE_TIMEOUT)
        buffer = b""
        try:
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(65535)
                except (socket.timeout, OSError):
                    break
                if not chunk:
                    break
                buffer += chunk
                buffer = self._drain(buffer, sender)
        finally:
            if buffer.strip():
                self.feed(buffer, sender)
            conn.close()
            with self._lock:
                self._connections -= 1
                self.stats["tcp_connections"] = self._connections

    def _drain(self, buffer: bytes, sender: str) -> bytes:
        """Take every complete message out of `buffer` (newline-framed, or octet-counted as in RFC 6587)."""
        while buffer:
            m = _OCTET_COUNT.match(buffer)
            if m:
                size = int(m[1])
                if len(buffer) < m.end() + size:
                    break
                self.feed(buffer[m.end():m.end() + size], sender)
                buffer = buffer[m.end() + size:]
                continue
            end = buffer.find(b"\n")
            if end == -1:
                if len(buffer) > syslog_lines.MAX_LINE * 2:  # a sender that never ends its line
                    self.feed(buffer[:syslog_lines.MAX_LINE], sender)
                    return b""
                break
            if buffer[:end].strip():
                self.feed(buffer[:end], sender)
            buffer = buffer[end + 1:]
        return buffer

    def _flush_loop(self) -> None:
        while not self._stop.wait(self.flush_interval):
            try:
                self.flush()
            except Exception:
                log.exception("flushing syslog messages failed")

    def stop(self) -> None:
        self._stop.set()
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass
        try:
            self.flush()
        except Exception:
            log.exception("final syslog flush failed")

    def status(self) -> dict:
        with self._lock:
            return {"enabled": True, "bind": self.bind, "port": self.port, "queued": len(self._queue), **self.stats}
