import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

CODE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = CODE_DIR.parent
LOG_DIR = PROJECT_DIR / "logs"


def ensure_dirs() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)

def new_run_id() -> str:
    return f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"

def run_dir(run_id: str) -> Path:
    return LOG_DIR / run_id

def write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def list_runs() -> List[Dict[str, Any]]:
    ensure_dirs()
    items: List[Dict[str, Any]] = []
    for p in sorted(LOG_DIR.iterdir(), reverse=True):
        if not p.is_dir():
            continue
        meta = p / "meta.json"
        if meta.exists():
            try:
                obj = read_json(meta)
                items.append(obj)
            except Exception:
                items.append({"run_id": p.name, "status": "corrupt_meta"})
        else:
            items.append({"run_id": p.name, "status": "no_meta"})
    return items

def get_run_meta(run_id: str) -> Optional[Dict[str, Any]]:
    p = run_dir(run_id) / "meta.json"
    if not p.exists():
        return None
    try:
        return read_json(p)
    except Exception:
        return None
