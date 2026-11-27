"""Loopback-only review UI for the synthetic TIP simulation.

Run: python simulation_server.py --port 8766 --db simulation-runs.sqlite3
License: TIPCL-1.0 (see ../../LICENSE.txt).
"""
from __future__ import annotations

import argparse
import importlib
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

MAX_BODY_BYTES = 256 * 1024
RUN_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
DOMAINS = {"healthcare", "finance", "government", "education", "privacy"}
UI_PATH = Path(__file__).with_name("simulation_ui.html")


def make_server(db_path: str | Path, port: int = 8766, *, backend=None) -> ThreadingHTTPServer:
    """Create a server bound only to IPv4 loopback; port=0 supports HTTP tests."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("Port must be between 0 and 65535")
    backend = backend or importlib.import_module("simulation")
    database = Path(db_path).expanduser().resolve()
    lock = threading.RLock()
    ui = UI_PATH.read_bytes()

    class Handler(BaseHTTPRequestHandler):
        server_version = "TIPReview/1.0"
        sys_version = ""
        protocol_version = "HTTP/1.0"

        def setup(self):
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, fmt, *args):
            # Avoid recording scenario content, query parameters or identifiers.
            pass

        def respond(self, status, body, content_type="application/json; charset=utf-8"):
            if not isinstance(body, bytes):
                body = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def trusted_request(self):
            port = self.server.server_port
            hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
            host_values = self.headers.get_all("Host", [])
            if len(host_values) != 1 or host_values[0] not in hosts:
                self.respond(403, {"error": "Use this review server through its localhost URL."})
                return False
            origins = self.headers.get_all("Origin", [])
            if len(origins) > 1 or (origins and origins[0] != f"http://{host_values[0]}"):
                self.respond(403, {"error": "Cross-origin requests are not allowed."})
                return False
            if self.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
                self.respond(403, {"error": "Open the reviewer directly on localhost."})
                return False
            return True

        def route(self):
            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
                self.respond(404, {"error": "Route not found."})
                return None
            return parsed.path

        def parse_object(self, text):
            def invalid_constant(value):
                raise ValueError("JSON must contain finite numbers")
            def unique_fields(items):
                result = {}
                for key, value in items:
                    if key in result:
                        raise ValueError("Duplicate JSON field")
                    result[key] = value
                return result
            try:
                parser = getattr(backend, "strict_json", None)
                doc = parser(text) if parser else json.loads(text, parse_constant=invalid_constant, object_pairs_hook=unique_fields)
                if not isinstance(doc, dict):
                    raise ValueError("Provide a JSON object.")
                return doc
            except (UnicodeError, RecursionError) as error:
                raise ValueError("Invalid or excessively nested JSON.") from error

        def read_json(self):
            if self.headers.get("Transfer-Encoding") is not None:
                self.respond(400, {"error": "Chunked request bodies are not supported."})
                return None
            types = self.headers.get_all("Content-Type", [])
            if len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != "application/json":
                self.respond(415, {"error": "Use application/json."})
                return None
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not lengths[0].isdigit():
                self.respond(411, {"error": "A single Content-Length is required."})
                return None
            size = int(lengths[0])
            if size > MAX_BODY_BYTES:
                self.respond(413, {"error": "Request body exceeds 256 KiB."})
                return None
            try:
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError("incomplete body")
                return self.parse_object(raw.decode("utf-8"))
            except (ValueError, UnicodeError, RecursionError):
                self.respond(400, {"error": "Send a valid JSON object without duplicate fields, excessive nesting or non-finite numbers."})
                return None

        def stored(self, run_id):
            if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
                raise ValueError("Invalid run identifier")
            result = backend.load_run(database, run_id)
            if result is None:
                raise KeyError(run_id)
            return result

        def do_GET(self):
            if not self.trusted_request():
                return
            path = self.route()
            if path is None:
                return
            try:
                with lock:
                    if path == "/":
                        self.respond(200, ui, "text/html; charset=utf-8")
                    elif path == "/api/presets":
                        self.respond(200, {"presets": backend.presets()})
                    elif path == "/api/runs":
                        self.respond(200, {"runs": backend.list_runs(database)})
                    elif path.startswith("/api/runs/"):
                        self.respond(200, {"bundle": self.stored(path.removeprefix("/api/runs/"))})
                    else:
                        self.respond(404, {"error": "Route not found."})
            except (KeyError, FileNotFoundError):
                self.respond(404, {"error": "Saved run not found."})
            except ValueError as error:
                self.respond(400, {"error": str(error)})
            except Exception:
                self.respond(500, {"error": "The review operation failed. Check the local server and try again."})

        def do_POST(self):
            if not self.trusted_request():
                return
            path = self.route()
            if path is None:
                return
            if path not in {"/api/generate", "/api/runs", "/api/verify", "/api/replay"}:
                self.respond(404, {"error": "Route not found."})
                return
            doc = self.read_json()
            if doc is None:
                return
            try:
                with lock:
                    expected = {"/api/generate": {"domain", "seed", "count"}, "/api/runs": {"scenario"},
                                "/api/verify": {"run_id"}, "/api/replay": {"run_id"}}[path]
                    if path == "/api/runs" and set(doc) not in ({"scenario"}, {"scenario_json"}):
                        raise ValueError("Provide exactly one of scenario or scenario_json.")
                    if path != "/api/runs" and set(doc) != expected:
                        raise ValueError("Provide exactly these fields: " + ", ".join(sorted(expected)))
                    if path == "/api/generate":
                        domain, seed, count = doc.get("domain"), doc.get("seed"), doc.get("count")
                        if domain not in DOMAINS or type(seed) is not int or type(count) is not int:
                            raise ValueError("Choose a supported domain, integer seed and request count.")
                        if not 0 <= seed <= 2**32 - 1 or not 1 <= count <= 200:
                            raise ValueError("Seed must be 0–4294967295 and event count 1–200.")
                        self.respond(200, {"scenario": backend.generate_scenario(domain, seed, count)})
                    elif path == "/api/runs":
                        if "scenario_json" in doc:
                            if not isinstance(doc["scenario_json"], str):
                                raise ValueError("scenario_json must contain the raw JSON text.")
                            scenario = self.parse_object(doc["scenario_json"])
                        else:
                            scenario = doc.get("scenario")
                        if not isinstance(scenario, dict):
                            raise ValueError("Provide a scenario object.")
                        self.respond(201, {"run": backend.run_scenario(scenario, database)})
                    elif path == "/api/verify":
                        self.respond(200, {"verification": backend.verify_run(self.stored(doc.get("run_id")))})
                    else:
                        self.respond(200, {"replay": backend.replay_run(self.stored(doc.get("run_id")))})
            except (KeyError, FileNotFoundError):
                self.respond(404, {"error": "Saved run not found."})
            except ValueError as error:
                self.respond(400, {"error": str(error)})
            except Exception:
                self.respond(500, {"error": "The review operation failed. Check the local server and try again."})

        def do_OPTIONS(self):
            if self.trusted_request():
                self.respond(405, {"error": "Use GET or POST. Cross-origin access is disabled."})

        def do_HEAD(self):
            if self.trusted_request():
                self.respond(405, {"error": "Use GET or POST."})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description="Local reviewer for synthetic TIP evidence; no external systems are contacted.")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--db", type=Path, default=Path("simulation-runs.sqlite3"))
    args = parser.parse_args()
    server = make_server(args.db, args.port)
    print(f"TIP synthetic reviewer: http://127.0.0.1:{server.server_port}/", flush=True)
    print(f"Local run database: {args.db.resolve()}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
