from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api/watcher", tags=["watcher"])


def _service(request: Request):
    return getattr(request.app.state, "watcher", None)


@router.get("/status")
def status(request: Request):
    service = _service(request)
    return service.status() if service else {"enabled": False}


@router.post("/pause")
def pause(request: Request):
    service = _service(request)
    if service is None:
        raise HTTPException(409, "Live monitoring is not enabled (set HORIZON_WATCH_DIR).")
    service.pause()
    return service.status()


@router.post("/resume")
def resume(request: Request):
    service = _service(request)
    if service is None:
        raise HTTPException(409, "Live monitoring is not enabled (set HORIZON_WATCH_DIR).")
    service.resume()
    return service.status()
