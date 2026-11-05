from datetime import datetime

import sentinel


def make_logs(tmp_path):
    (tmp_path / "a.log").write_text(
        "2026-10-31 09:00:01 agent started as svc\n"
        "2026-11-03 14:22:10 downloading insight.bundle\n"
        "undated line mentioning K2F_CHAN\n"
    )
    (tmp_path / "clean.log").write_text("2026-11-04 08:00:00 all good\n")
    (tmp_path / "payload.exe").write_bytes(b"k2f_chan")  # wrong extension: must be skipped
    return tmp_path


def test_detects_indicators(tmp_path):
    findings, scanned = sentinel.scan(make_logs(tmp_path), sentinel.load_iocs(sentinel.DEFAULT_IOCS))
    assert scanned == 2
    assert set(findings) == {"k2f_chan", "insight_bundle", "agent_started"}
    assert len(findings["k2f_chan"]["events"]) == 1  # case-insensitive, .exe ignored


def test_no_false_positives(tmp_path):
    (tmp_path / "ok.log").write_text("2026-11-04 08:00:00 nothing to see\n")
    findings, _ = sentinel.scan(tmp_path, sentinel.load_iocs(sentinel.DEFAULT_IOCS))
    assert findings == {}


def test_historical_vs_new(tmp_path):
    findings, _ = sentinel.scan(make_logs(tmp_path), sentinel.load_iocs(sentinel.DEFAULT_IOCS))
    assert "Historical" in sentinel.assess(findings, datetime(2026, 11, 4))[0]
    assert "NEW" in sentinel.assess(findings, datetime(2026, 11, 1))[0]
    assert sentinel.assess(findings, None)[1] == "UNKNOWN"
