"""Server-sent events: the dashboard keeps one open connection and refreshes when something changes."""
import asyncio
import json

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app.live.bus import TooManySubscribers, bus

router = APIRouter(prefix="/api", tags=["live"])
KEEPALIVE_SECONDS = 15.0


async def event_stream(request: Request, limit: int | None, keepalive: float = KEEPALIVE_SECONDS):
    queue = bus.subscribe()
    sent = 0
    try:
        yield "retry: 3000\n\n"
        yield ": connected\n\n"
        while limit is None or sent < limit:
            if await request.is_disconnected():
                break
            try:
                message = await asyncio.wait_for(queue.get(), timeout=keepalive)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"  # keeps proxies from closing an idle connection
                continue
            sent += 1
            yield f"event: change\ndata: {json.dumps(message)}\n\n"
    finally:
        bus.unsubscribe(queue)


@router.get("/stream")
async def stream(request: Request, limit: int | None = Query(None, ge=1, le=1000, include_in_schema=False)):
    """An `EventSource` endpoint. Each `change` event says which data changed: `{"changed": ["alerts", "events"]}`."""
    if bus.subscribers >= bus.max_subscribers:
        raise HTTPException(503, "Too many dashboards are open.")
    try:
        generator = event_stream(request, limit)
    except TooManySubscribers as exc:  # pragma: no cover (checked above; kept for a race)
        raise HTTPException(503, str(exc)) from exc
    return StreamingResponse(generator, media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})
