"""Sentinel API. Run: uvicorn api:app --host 127.0.0.1 --port 8000

Scanning is restricted to SENTINEL_ROOT (default: ./samples) so the API
cannot be used to read arbitrary paths on the machine.
"""
import json
import os
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

import sentinel

BASE = Path(__file__).parent
ROOT = Path(os.environ.get("SENTINEL_ROOT", BASE / "samples")).resolve()
app = FastAPI(title="Sentinel")


class ScanRequest(BaseModel):
    path: str = "."
    since: str | None = None  # YYYY-MM-DD


@app.post("/api/scan")
def api_scan(req: ScanRequest):
    target = (ROOT / req.path).resolve()
    if not target.is_relative_to(ROOT):
        raise HTTPException(403, f"Path must be inside {ROOT}")
    if not target.exists():
        raise HTTPException(404, f"Path not found under {ROOT}. Set SENTINEL_ROOT or create that folder.")
    try:
        since = datetime.strptime(req.since, "%Y-%m-%d") if req.since else None
    except ValueError:
        raise HTTPException(422, "since must be YYYY-MM-DD")

    try:
        iocs = sentinel.load_iocs(sentinel.DEFAULT_IOCS)
    except ValueError as e:
        raise HTTPException(500, str(e))
    findings, scanned = sentinel.scan(target, iocs)
    verdict, status = sentinel.assess(findings, since)
    return {
        "root": str(ROOT),
        "files_scanned": scanned,
        "assessment": verdict,
        "infection_status": status,
        "timeline": [{"day": d, "event": e} for d, e in sentinel.timeline(findings)],
        "findings": [
            {
                "name": n,
                "label": f["ioc"]["label"],
                "severity": f["ioc"]["severity"],
                "confidence": f["ioc"]["confidence"],
                "note": f["ioc"].get("note", ""),
                "matches": len(f["events"]),
                "files": len({e["file"] for e in f["events"]}),
                "evidence": [
                    {"file": Path(e["file"]).name, "line": e["line"], "text": e["text"],
                     "ts": e["ts"].isoformat(sep=" ") if e["ts"] else None}
                    for e in f["events"][:10]
                ],
            }
            for n, f in findings.items()
        ],
    }


@app.get("/api/persistence")
def api_persistence():
    p = BASE / "persistence.json"
    if not p.exists():
        raise HTTPException(404, "Run persistence_check.ps1 first")
    return json.loads(p.read_text(encoding="utf-8-sig"))


@app.get("/")
def index():
    # Tolerate a flattened download where index.html sits next to api.py
    for p in (BASE / "dashboard" / "index.html", BASE / "index.html"):
        if p.exists():
            return FileResponse(p)
    raise HTTPException(404, "dashboard/index.html not found. Keep the folder layout from the README.")
