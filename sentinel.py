#!/usr/bin/env python3
"""Sentinel: read-only log scanner for known indicators of compromise (IOCs).

Safety: files are only opened as text and searched. Nothing is executed,
imported, or loaded from the scanned directory.

Usage:
    python sentinel.py scan "C:\\NIKKE\\Launcher"
    python sentinel.py scan ./logs --since 2026-11-04 --report report.md
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

TEXT_EXT = {".log", ".txt", ".json", ".xml", ".ini", ".cfg", ".csv", ".yaml", ".yml", ".out", ""}
MAX_BYTES = 50 * 1024 * 1024
TS_RE = re.compile(r"(\d{4})[-/](\d{2})[-/](\d{2})[ T](\d{2}):(\d{2}):(\d{2})")
# Chromium/CEF style: [1103/070734.809] = MMDD/HHMMSS.mmm (no year), often inside [pid:tid:1103/070734.809:LEVEL:...]
CHROMIUM_RE = re.compile(r"(?<!\d)(\d{2})(\d{2})/(\d{2})(\d{2})(\d{2})\.\d{3}(?!\d)")
REQUIRED_KEYS = ("name", "label", "pattern", "severity", "confidence")
DEFAULT_IOCS = Path(__file__).with_name("iocs.json")


def load_iocs(path):
    """Load and validate the IOC file. Raises ValueError with a clear message."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as e:
        raise ValueError(f"cannot read IOC file {path}: {e}")
    if not isinstance(data, dict) or not isinstance(data.get("indicators"), list):
        raise ValueError("IOC file must be an object with an 'indicators' list")
    iocs = []
    for n, i in enumerate(data["indicators"]):
        if not isinstance(i, dict):
            raise ValueError(f"indicator #{n}: must be an object")
        missing = [k for k in REQUIRED_KEYS if not isinstance(i.get(k), str) or not i[k]]
        if missing:
            raise ValueError(f"indicator #{n} ({i.get('name', '?')}): missing/invalid {missing}")
        pat = i["pattern"] if i.get("regex") else re.escape(i["pattern"])
        try:
            i["_re"] = re.compile(pat, re.I)
        except re.error as e:
            raise ValueError(f"indicator '{i['name']}': invalid regex: {e}")
        iocs.append(i)
    return iocs


def parse_ts(line, ref=None):
    """Parse a timestamp from a log line; return None if absent or invalid.

    ref (the file's modified time) supplies the year for Chromium-style
    stamps, which have none. A stamp later than ref is assumed to be last year.
    """
    m = TS_RE.search(line)
    try:
        if m:
            return datetime(*map(int, m.groups()))
        m = CHROMIUM_RE.search(line)
        if m and ref:
            mo, d, h, mi, sec = map(int, m.groups())
            ts = datetime(ref.year, mo, d, h, mi, sec)
            if ts > ref + timedelta(days=1):
                ts = ts.replace(year=ref.year - 1)
            return ts
    except ValueError:  # e.g. month 13, Feb 30, 25:00:00
        return None
    return None


def iter_files(root):
    """Yield scannable text files. Symlinks are never followed or read."""
    root = Path(root)
    if root.is_file():
        candidates = [root]
    else:
        candidates = (Path(d) / f for d, _, fs in os.walk(root, followlinks=False) for f in sorted(fs))
    for p in candidates:
        if p != root and p.is_symlink():
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if p.suffix.lower() in TEXT_EXT and size <= MAX_BYTES:
            yield p


def scan(root, iocs):
    """Return (findings, files_scanned). Findings are keyed by IOC name."""
    findings, scanned = {}, 0
    for path in iter_files(root):
        scanned += 1
        last_ts = None
        try:
            ref = datetime.fromtimestamp(path.stat().st_mtime)
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    ts = parse_ts(line, ref) or last_ts  # carry forward for undated lines
                    last_ts = ts
                    for ioc in iocs:
                        if ioc["_re"].search(line):
                            f = findings.setdefault(ioc["name"], {"ioc": ioc, "events": []})
                            f["events"].append({"ts": ts, "file": str(path), "line": n,
                                                "text": line.strip()[:140]})
        except (OSError, UnicodeError) as e:
            print(f"[warn] could not read {path}: {e}", file=sys.stderr)
    return findings, scanned


def assess(findings, since):
    if not findings:
        return "No known indicators found in the scanned files.", "UNKNOWN"
    stamped = [e["ts"] for f in findings.values() for e in f["events"] if e["ts"]]
    if since and any(t >= since for t in stamped):
        return "NEW activity observed after the cutoff. Investigate now.", "UNKNOWN"
    if since and stamped and not any(t >= since for t in stamped):
        return "Historical suspicious activity detected (none after cutoff).", "UNKNOWN"
    return "Historical suspicious activity detected.", "UNKNOWN"


def fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M") if ts else "unknown time"


def render_console(findings, scanned, since):
    out = ["SENTINEL SECURITY SCAN", "-" * 28, f"Files scanned: {scanned}", ""]
    for name, f in sorted(findings.items(), key=lambda kv: kv[1]["ioc"]["severity"]):
        ev, ioc = f["events"], f["ioc"]
        stamps = sorted(e["ts"] for e in ev if e["ts"])
        out += [f"[DETECTED] {ioc['label']}",
                f"  Matches: {len(ev)}",
                f"  Matching log files: {len({e['file'] for e in ev})}",
                f"  Confidence: {ioc['confidence']}  Severity: {ioc['severity']}",
                f"  First/last seen: {fmt(stamps[0]) if stamps else '?'} / {fmt(stamps[-1]) if stamps else '?'}",
                f"  Evidence: {ev[0]['text']}", ""]
    out.append("INCIDENT TIMELINE")
    for ts, name in timeline(findings):
        out.append(f"  {ts}  {name}")
    verdict, status = assess(findings, since)
    out += ["", "-" * 28, "Assessment:", verdict, "", "Current infection status:", status]
    return "\n".join(out)


def timeline(findings):
    """One row per (day, indicator), sorted; undated events go last."""
    seen = {}
    for name, f in findings.items():
        for e in f["events"]:
            day = e["ts"].strftime("%Y-%m-%d") if e["ts"] else "undated"
            seen.setdefault((day, f["ioc"]["label"]), 0)
            seen[(day, f["ioc"]["label"])] += 1
    return [(d, f"{label} (x{c})") for (d, label), c in sorted(seen.items(), key=lambda kv: (kv[0][0] == "undated", kv[0]))]


def render_report(findings, scanned, since, target):
    verdict, status = assess(findings, since)
    md = [f"# Sentinel Investigation Report", "",
          f"- Target: `{target}`", f"- Generated: {datetime.now():%Y-%m-%d %H:%M}",
          f"- Files scanned: {scanned}", "", "## Assessment", verdict, "",
          f"**Current infection status: {status}**", "", "## Findings"]
    for f in findings.values():
        ioc = f["ioc"]
        md += [f"### {ioc['label']}", f"- Confidence: {ioc['confidence']} | Severity: {ioc['severity']}",
               f"- Matches: {len(f['events'])}", f"- Note: {ioc.get('note', '')}", "- Evidence:"]
        md += [f"  - `{Path(e['file']).name}:{e['line']}` ({fmt(e['ts'])}): `{e['text']}`" for e in f["events"][:5]]
        md.append("")
    md += ["## Timeline"] + [f"- {d}: {t}" for d, t in timeline(findings)]
    md += ["", "## What remains uncertain",
           "- Logs show past events only. They cannot prove the system is clean or infected today.",
           "- Low-confidence indicators (e.g. generic phrases) may be benign application behavior.",
           "- Missing, rotated, or deleted logs are not visible to this scan.",
           "- Next step: check persistence locations (Run keys, scheduled tasks, services) and run an AV/EDR scan."]
    return "\n".join(md)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sentinel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a directory or file of logs")
    s.add_argument("path")
    s.add_argument("--iocs", default=str(DEFAULT_IOCS))
    s.add_argument("--since", help="YYYY-MM-DD; matches before this date count as historical")
    s.add_argument("--report", help="write a Markdown report to this path")
    s.add_argument("--json", action="store_true", help="print machine-readable results")
    a = ap.parse_args(argv)

    if not Path(a.path).exists():
        print(f"error: {a.path} does not exist", file=sys.stderr)
        return 2
    since = datetime.strptime(a.since, "%Y-%m-%d") if a.since else None
    try:
        iocs = load_iocs(a.iocs)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    findings, scanned = scan(a.path, iocs)

    if a.json:
        print(json.dumps({n: {"matches": len(f["events"]),
                              "files": sorted({e["file"] for e in f["events"]}),
                              "confidence": f["ioc"]["confidence"]} for n, f in findings.items()}, indent=2))
    else:
        print(render_console(findings, scanned, since))
    if a.report:
        Path(a.report).write_text(render_report(findings, scanned, since, a.path), encoding="utf-8")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
