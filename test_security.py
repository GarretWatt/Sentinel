import json
import os
import sys
from datetime import datetime

import pytest

import sentinel

IOCS = sentinel.DEFAULT_IOCS


def scan_dir(path):
    return sentinel.scan(path, sentinel.load_iocs(IOCS))


# --- timestamps -------------------------------------------------------------
def test_chromium_timestamp_with_ref_year():
    ref = datetime(2026, 11, 5)
    line = "[12345:6789:1103/070734.809:ERROR:agent] insight.bundle"
    assert sentinel.parse_ts(line, ref) == datetime(2026, 11, 3, 7, 7, 34)


def test_chromium_timestamp_year_rollover():
    # a Dec stamp in a file last modified in January belongs to the previous year
    assert sentinel.parse_ts("[1231/235959.000]", datetime(2027, 1, 2)) == datetime(2026, 12, 31, 23, 59, 59)


def test_chromium_timestamp_needs_ref():
    assert sentinel.parse_ts("[1103/070734.809]") is None


@pytest.mark.parametrize("line", [
    "2026-13-45 99:99:99 nonsense",     # impossible date
    "[1332/256199.000]",                # impossible chromium stamp
    "2026-02-30 10:00:00 feb thirty",
    "version 1.2.3 build 20261103",     # digits that are not a timestamp
    "",
])
def test_unusual_timestamps_do_not_crash(line):
    assert sentinel.parse_ts(line, datetime(2026, 11, 5)) is None


def test_chromium_log_end_to_end(tmp_path):
    (tmp_path / "cef.log").write_text("[1103/070734.809:INFO:x] downloading insight.bundle\n")
    findings, _ = scan_dir(tmp_path)
    ev = findings["insight_bundle"]["events"][0]
    assert ev["ts"].month == 11 and ev["ts"].day == 3


# --- filesystem safety ------------------------------------------------------
@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside"; outside.mkdir()
    (outside / "secret.log").write_text("k2f_chan\n")
    root = tmp_path / "root"; root.mkdir()
    (root / "link_dir").symlink_to(outside, target_is_directory=True)
    (root / "link_file.log").symlink_to(outside / "secret.log")
    findings, scanned = scan_dir(root)
    assert scanned == 0 and findings == {}


@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="chmod 000 is not enforced for root/Windows")
def test_unreadable_file_is_skipped(tmp_path, capsys):
    bad = tmp_path / "locked.log"; bad.write_text("k2f_chan\n"); bad.chmod(0)
    (tmp_path / "ok.log").write_text("insight.bundle\n")
    try:
        findings, _ = scan_dir(tmp_path)
    finally:
        bad.chmod(0o600)
    assert "insight_bundle" in findings and "k2f_chan" not in findings
    assert "could not read" in capsys.readouterr().err


def test_binary_and_invalid_utf8_do_not_crash(tmp_path):
    (tmp_path / "junk.log").write_bytes(b"\xff\xfe\x00k2f_chan\x80\x81\n")
    findings, _ = scan_dir(tmp_path)
    assert "k2f_chan" in findings


def test_oversized_file_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(sentinel, "MAX_BYTES", 10)
    (tmp_path / "big.log").write_text("k2f_chan " * 10)
    assert scan_dir(tmp_path) == ({}, 0)


def test_scanned_content_is_never_executed(tmp_path):
    marker = tmp_path / "pwned.txt"
    (tmp_path / "evil.log").write_text(f"k2f_chan __import__('os').system('touch {marker}')\n")
    scan_dir(tmp_path)
    assert not marker.exists()


# --- IOC file validation ----------------------------------------------------
def write_iocs(tmp_path, content):
    p = tmp_path / "bad.json"
    p.write_text(content if isinstance(content, str) else json.dumps(content))
    return p


@pytest.mark.parametrize("content", [
    "{not json",
    "[]",
    {"indicators": "nope"},
    {"indicators": ["string"]},
    {"indicators": [{"name": "x"}]},  # missing keys
    {"indicators": [{"name": "x", "label": "x", "pattern": "([", "regex": True,
                     "severity": "low", "confidence": "low"}]},  # invalid regex
])
def test_malformed_iocs_raise_clear_error(tmp_path, content):
    with pytest.raises(ValueError):
        sentinel.load_iocs(write_iocs(tmp_path, content))


def test_missing_ioc_file_raises(tmp_path):
    with pytest.raises(ValueError):
        sentinel.load_iocs(tmp_path / "nope.json")


def test_cli_returns_2_on_bad_iocs(tmp_path):
    bad = write_iocs(tmp_path, "{oops")
    assert sentinel.main(["scan", str(tmp_path), "--iocs", str(bad)]) == 2
