"""Actual loopback HTTP checks for the local synthetic reviewer."""
from __future__ import annotations

import http.client as http_client
import json
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from simulation_server import MAX_BODY_BYTES, make_server


@contextmanager
def running(path, backend=None):
    server = make_server(path, port=0, backend=backend)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def http(server, method, path, doc=None, headers=None, raw=None):
    conn = http_client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    body = raw if raw is not None else (json.dumps(doc).encode() if doc is not None else None)
    outgoing = {"Content-Type": "application/json"} if body is not None else {}
    outgoing.update(headers or {})
    try:
        conn.request(method, path, body=body, headers=outgoing)
        response = conn.getresponse()
        data = response.read()
        payload = json.loads(data) if data and "application/json" in response.getheader("Content-Type", "") else data
        return response.status, payload, dict(response.getheaders())
    finally:
        conn.close()


@pytest.fixture
def stub():
    calls = []
    def load(path, run_id):
        calls.append(("load", str(path), run_id))
        raise KeyError(run_id)
    return SimpleNamespace(calls=calls, presets=lambda: [], list_runs=lambda path: [], load_run=load,
        generate_scenario=lambda *args: {"generated": list(args)}, run_scenario=lambda *args: calls.append(args),
        verify_run=lambda *args: {"valid": True, "errors": []}, replay_run=lambda *args: {"matches": True, "errors": []})


def test_ui_is_loopback_only_and_has_no_external_asset_dependency(tmp_path, stub):
    with running(tmp_path / "runs.sqlite3", stub) as server:
        assert server.server_address[0] == "127.0.0.1"
        status, body, headers = http(server, "GET", "/")
        assert status == 200
        assert b"TIP evidence reviewer" in body
        assert b"Synthetic inputs and outcomes" in body
        assert b'<script src=' not in body and b'<link ' not in body
        assert headers["Cache-Control"] == "no-store"
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
        assert "Access-Control-Allow-Origin" not in headers
        assert http(server, "GET", "/api/presets")[1] == {"presets": []}


@pytest.mark.parametrize("header", [
    {"Host": "attacker.example"}, {"Host": "127.0.0.1"}, {"Origin": "https://attacker.example"},
    {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"},
])
def test_foreign_hosts_origins_and_fetch_contexts_are_denied(tmp_path, stub, header):
    with running(tmp_path / "runs.sqlite3", stub) as server:
        assert http(server, "POST", "/api/runs", {"scenario": {}}, header)[0] == 403
        assert stub.calls == []


def test_matching_origin_is_accepted_and_duplicate_host_is_rejected(tmp_path, stub):
    with running(tmp_path / "runs.sqlite3", stub) as server:
        origin = f"http://127.0.0.1:{server.server_port}"
        assert http(server, "GET", "/api/runs", headers={"Origin": origin, "Sec-Fetch-Site": "same-origin"})[0] == 200
        conn = http_client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            conn.putrequest("GET", "/", skip_host=True)
            conn.putheader("Host", f"127.0.0.1:{server.server_port}")
            conn.putheader("Host", "attacker.example")
            conn.endheaders()
            assert conn.getresponse().status == 403
        finally:
            conn.close()


@pytest.mark.parametrize("raw,headers,expected", [
    (b"{}", {"Content-Type": "text/plain"}, 415),
    (b"{}", {"Content-Length": str(MAX_BODY_BYTES + 1)}, 413),
    (b"{}", {"Transfer-Encoding": "chunked"}, 400),
    (b"{broken", {}, 400), (b"[]", {}, 400), (b'{"x":NaN}', {}, 400), (b"\xff", {}, 400),
])
def test_invalid_write_bodies_do_not_reach_backend(tmp_path, stub, raw, headers, expected):
    with running(tmp_path / "runs.sqlite3", stub) as server:
        assert http(server, "POST", "/api/runs", raw=raw, headers=headers)[0] == expected
        assert stub.calls == []


def test_only_known_routes_and_identifiers_can_access_evidence(tmp_path, stub):
    with running(tmp_path / "runs.sqlite3", stub) as server:
        for path in ["/simulation_server.py", "/../simulation_ui.html", "/api/runs?path=/tmp/secret", "http://attacker.example/api/runs"]:
            assert http(server, "GET", path, headers={"Host": f"127.0.0.1:{server.server_port}"})[0] == 404
        assert http(server, "GET", "/api/runs/../../secret")[0] == 400
        assert http(server, "POST", "/api/verify", {"run_id": "../../secret"})[0] == 400
        assert stub.calls == []
        assert http(server, "GET", "/api/runs/not-found")[0] == 404
        assert len(stub.calls) == 1


@pytest.mark.parametrize("doc", [
    {"domain": "finance", "seed": 0, "count": 201}, {"domain": "finance", "seed": True, "count": 10},
    {"domain": "other", "seed": 1, "count": 10}, {"domain": "finance", "seed": -1, "count": 10},
])
def test_generator_bounds_are_enforced_at_http_boundary(tmp_path, stub, doc):
    with running(tmp_path / "runs.sqlite3", stub) as server:
        assert http(server, "POST", "/api/generate", doc)[0] == 400


def test_http_persisted_run_reopens_verifies_and_replays_after_server_restart(tmp_path):
    # Actual simulation backend, actual SQLite, real signatures; no HTTP mocks.
    path = tmp_path / "persisted.sqlite3"
    with running(path) as server:
        status, data, _ = http(server, "GET", "/api/presets")
        assert status == 200
        assert {s["domain"] for s in data["presets"]} == {"healthcare", "finance", "government", "education", "privacy"}
        status, generated, _ = http(server, "POST", "/api/generate", {"domain": "finance", "seed": 42, "count": 8})
        assert status == 200
        status, data, _ = http(server, "POST", "/api/runs", {"scenario": generated["scenario"]})
        assert status == 201, data
        original = data["run"]
        run_id = original["run_id"]
        assert original["trace"] and original["receipts"]
        assert http(server, "GET", "/api/runs")[1]["runs"][0]["run_id"] == run_id
    assert path.is_file()
    with running(path) as server:
        status, reopened, _ = http(server, "GET", f"/api/runs/{run_id}")
        assert status == 200 and reopened["bundle"] == original
        status, verified, _ = http(server, "POST", "/api/verify", {"run_id": run_id})
        assert status == 200 and verified["verification"]["valid"], verified
        status, replayed, _ = http(server, "POST", "/api/replay", {"run_id": run_id})
        assert status == 200 and replayed["replay"]["matches"], replayed

@pytest.mark.parametrize("raw", [b'{"scenario":{},"scenario":{}}', b'{"scenario":{"id":"one","id":"two"}}'])
def test_duplicate_json_fields_are_rejected_before_backend(tmp_path, stub, raw):
    with running(tmp_path / "runs.sqlite3", stub) as server:
        assert http(server, "POST", "/api/runs", raw=raw)[0] == 400
        assert stub.calls == []


def test_excessively_nested_json_returns_error_and_server_remains_usable(tmp_path, stub):
    with running(tmp_path / "runs.sqlite3", stub) as server:
        raw = b'{"scenario":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}'
        assert http(server, "POST", "/api/runs", raw=raw)[0] == 400
        assert http(server, "GET", "/api/presets")[0] == 200
        assert stub.calls == []


def test_unknown_api_fields_and_boolean_port_are_rejected(tmp_path, stub):
    with pytest.raises(ValueError):
        make_server(tmp_path / "runs.sqlite3", port=True, backend=stub)
    with running(tmp_path / "runs.sqlite3", stub) as server:
        assert http(server, "POST", "/api/runs", {"scenario": {}, "db_path": "/tmp/elsewhere"})[0] == 400
        assert http(server, "POST", "/api/verify", {"run_id": "saved123", "bundle": {}})[0] == 400
        assert stub.calls == []


def test_raw_editor_json_preserves_duplicates_for_strict_server_validation(tmp_path):
    import simulation
    scenario = simulation.generate_scenario("healthcare", 12, 6)
    raw = json.dumps(scenario)
    # A duplicated nested field must reach the strict parser unchanged, as text.
    duplicate = raw.replace('"shared_limit":', '"shared_limit": 999, "shared_limit":', 1)
    with running(tmp_path / "raw-editor.sqlite3") as server:
        assert http(server, "POST", "/api/runs", {"scenario_json": duplicate})[0] == 400
        assert http(server, "GET", "/api/runs")[1]["runs"] == []
        status, result, _ = http(server, "POST", "/api/runs", {"scenario_json": raw})
        assert status == 201, result
        assert result["run"]["scenario"] == scenario
        assert http(server, "POST", "/api/runs", {"scenario": scenario, "scenario_json": raw})[0] == 400
        assert len(http(server, "GET", "/api/runs")[1]["runs"]) == 1
        nested = '{"nested":' + '[' * 2000 + '0' + ']' * 2000 + '}'
        assert http(server, "POST", "/api/runs", {"scenario_json": nested})[0] == 400
        assert http(server, "POST", "/api/runs", {"scenario_json": {}})[0] == 400
