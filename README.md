# Sentinel

Read-only incident triage: log analysis, IOC matching, persistence checks, timeline, dashboard.

```
persistence_check.ps1 --> persistence.json --+
sentinel.py (scan)  ------------------------+--> api.py (FastAPI) --> dashboard/index.html (React)
iocs.json (indicators) feeds both checkers
```

## Layout (keep this structure)
```
sentinel/
  sentinel.py  api.py  iocs.json  persistence_check.ps1  requirements.txt
  test_sentinel.py  test_security.py  test_api.py
  dashboard/index.html
  samples/launcher.log
```
Download `sentinel.zip` to get this layout intact. If files arrived flat, create `dashboard/` and `samples/` and move
`index.html` and `launcher.log` into them. (`api.py` also falls back to an `index.html` next to it.)

## Run
```
pip install -r requirements.txt
python sentinel.py scan samples --report report.md      # CLI
powershell -ExecutionPolicy Bypass -File .\persistence_check.ps1   # Windows only
set SENTINEL_ROOT=C:\NIKKE\Launcher                      # PowerShell: $env:SENTINEL_ROOT="..."
uvicorn api:app --host 127.0.0.1 --port 8000             # open http://127.0.0.1:8000
pytest   # includes test_security.py
```
Scan paths in the dashboard are relative to `SENTINEL_ROOT` (default `./samples`).

## Design notes
- Timestamps: ISO (`2026-11-03 14:22:10`) and Chromium/CEF (`[1103/070734.809]`). The Chromium form has no year, so it
  is taken from the file's modified time (a stamp later than that is assumed to be last year).
- Symlinks are never followed; unreadable files are skipped with a warning; invalid IOC files fail with a clear error (exit 2).
- Never executes scanned content. Log text is rendered as escaped text in React.
- API binds to localhost and refuses paths outside `SENTINEL_ROOT`.
- Confidence levels reduce false positives: generic phrases ("agent started") are low confidence.
- Infection status is always UNKNOWN. Logs are historical evidence, not proof of current state.

## Limits / next ideas
- Add hash, domain and IP indicators to `iocs.json` (regex supported).
- Parse Windows .evtx events, correlate persistence entries with log timestamps.
- Dashboard loads React from cdnjs; bundle it with Vite for offline use.
