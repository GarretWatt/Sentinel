from fastapi.testclient import TestClient

import api

client = TestClient(api.app)


def test_scan_sample():
    r = client.post("/api/scan", json={"path": ".", "since": "2026-11-04"})
    assert r.status_code == 200
    body = r.json()
    assert body["infection_status"] == "UNKNOWN"
    assert {f["name"] for f in body["findings"]} == {"k2f_chan", "insight_bundle", "agent_started"}


def test_path_traversal_blocked():
    assert client.post("/api/scan", json={"path": "../.."}).status_code == 403
