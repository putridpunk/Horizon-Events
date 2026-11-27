"""A tiny in-process broadcast so the dashboard hears about new data at once instead of polling for it.

Messages are only hints that something changed ("events", "alerts"); the page then asks the API for the new data,
so a dropped message costs at most one poll interval. Publishing is safe from any thread.
"""
from __future__ import annotations

import asyncio
import threading

MAX_SUBSCRIBERS = 20
QUEUE_SIZE = 50


class TooManySubscribers(RuntimeError):
    pass


class LiveBus:
    def __init__(self, max_subscribers: int = MAX_SUBSCRIBERS):
        self.max_subscribers = max_subscribers
        self._subs: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = []
        self._lock = threading.Lock()

    def subscribe(self) -> asyncio.Queue:
        """Call from inside the event loop. The queue receives a dict per change."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        with self._lock:
            if len(self._subs) >= self.max_subscribers:
                raise TooManySubscribers("too many open dashboards")
            self._subs.append((asyncio.get_running_loop(), queue))
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        with self._lock:
            self._subs = [(loop, q) for loop, q in self._subs if q is not queue]

    @property
    def subscribers(self) -> int:
        with self._lock:
            return len(self._subs)

    def publish(self, *changed: str) -> None:
        """Tell every open dashboard that these kinds of data changed (for example "events", "alerts")."""
        if not changed:
            return
        message = {"changed": sorted(set(changed))}
        with self._lock:
            subs = list(self._subs)
        for loop, queue in subs:
            try:
                loop.call_soon_threadsafe(self._put, queue, message)
            except RuntimeError:  # that page's loop has closed; unsubscribe() will clean it up
                pass

    @staticmethod
    def _put(queue: asyncio.Queue, message: dict) -> None:
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            pass  # the page already has plenty of reasons to refresh


bus = LiveBus()
