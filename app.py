from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import List
import time
from ansi2html import Ansi2HTMLConverter
from code.runners import available_tools_config, run_scan
from code.storage import ensure_dirs, get_run_meta, list_runs, new_run_id, run_dir, write_json

app = FastAPI(title="Local Vulnerability Scanner")
ensure_dirs()

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

conv = Ansi2HTMLConverter(inline=True)

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/runs/{run_id}", response_class=HTMLResponse)
def run_page(run_id: str, request: Request):
    meta = get_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Run not found")
    return templates.TemplateResponse("run.html", {"request": request, "run_id": run_id})


@app.get("/api/tools")
def tools():
    return available_tools_config()


@app.get("/api/runs")
def runs():
    return list_runs()


@app.get("/api/runs/{run_id}")
def api_get_run(run_id: str):
    meta = get_run_meta(run_id)
    if meta is None:
        return {"run_id": run_id, "status": "missing"}
    return meta


@app.get("/api/runs/{run_id}/file")
def run_file(run_id: str, relpath: str):
    base = run_dir(run_id).resolve()
    target = (base / relpath).resolve()

    # Prevent path traversal outside the run directory
    if base not in target.parents and target != base:
        raise HTTPException(status_code=400, detail="Invalid path")

    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    text = target.read_text(errors="replace")
    html = conv.convert(text, full=False)

    return HTMLResponse(html)

@app.post("/api/run")
def api_run(
    background: BackgroundTasks,
    tools: List[str] = Query(default=[]),
):
    run_id = new_run_id()

    # Create run folder + initial meta immediately (prevents UI 404 polling)
    out_dir = run_dir(run_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "meta.json", {
        "run_id": run_id,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "queued",
        "tools_requested": tools,
        "tools": []
    })

    # IMPORTANT: run_scan takes only (run_id, tools)
    background.add_task(run_scan, run_id, tools)

    return {"run_id": run_id, "status": "started"}


@app.post("/runs")
def runs_alias(
    background: BackgroundTasks,
    tools: List[str] = Query(default=[]),
):
    return api_run(background=background, tools=tools)