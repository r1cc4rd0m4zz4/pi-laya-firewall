#!/usr/bin/env python3
"""Minimal local controller used by regression tests."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import URLError
from urllib.request import Request, urlopen


HOST = "127.0.0.1"
PORT = 5292
BASE_URL = f"http://{HOST}:{PORT}"
PID_FILE = "/tmp/pi_laya_firewall_test_server.pid"


def _health_ok(timeout: float = 0.4) -> bool:
    try:
        with urlopen(f"{BASE_URL}/health", timeout=timeout) as resp:
            return resp.status == 200
    except (URLError, OSError, TimeoutError):
        return False


def _routing_model(payload: dict[str, object]) -> str:
    model = str(payload.get("model") or "").strip()
    if model:
        return model
    lang = str(payload.get("lang") or "").lower()
    return "multilingual" if lang == "it" else "english"


def _is_exfiltration(state: str) -> bool:
    s = state.lower()
    return "curl" in s and "http" in s and "@" in s


class _Handler(BaseHTTPRequestHandler):
    server_version = "laya-test/1.0"

    def _json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self._json(404, {"error": "not found"})
            return
        self._json(200, {"status": "ok", "device": "cpu", "loaded": ["english", "multilingual", "typed-decisions"]})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/systemone":
            self._json(404, {"error": "not found"})
            return
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8") or "{}"
        payload = json.loads(raw)
        state = str(payload.get("state") or "")
        answers = {}
        for key, spec in (payload.get("questions") or {}).items():
            qtype = str((spec or {}).get("type") or "").lower()
            if qtype == "choice":
                answers[key] = {"choice": "covert_exfiltration" if _is_exfiltration(state) else "benign_dev"}
            elif qtype == "score":
                answers[key] = {"score": 2.6 if _is_exfiltration(state) else 0.1}
            elif qtype == "noul":
                answers[key] = {"noul": 0.99}
            else:
                answers[key] = {}
        self._json(200, {"routing": {"model": _routing_model(payload)}, "answers": answers})

    def log_message(self, _fmt: str, *_args: object) -> None:
        return


def _write_pid(pid: int) -> None:
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(pid))


def _read_pid() -> int | None:
    if not os.path.exists(PID_FILE):
        return None
    try:
        with open(PID_FILE, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _start() -> int:
    if _health_ok():
        return 0
    proc = subprocess.Popen(
        [sys.executable, __file__, "serve"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    _write_pid(proc.pid)
    for _ in range(30):
        if _health_ok():
            return 0
        time.sleep(0.1)
    return 1


def _stop() -> int:
    pid = _read_pid()
    if not pid:
        return 0
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass
    try:
        os.remove(PID_FILE)
    except OSError:
        pass
    return 0


def _status() -> int:
    return 0 if _health_ok() else 1


def _serve() -> int:
    server = ThreadingHTTPServer((HOST, PORT), _Handler)
    _write_pid(os.getpid())
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main() -> int:
    cmd = (sys.argv[1] if len(sys.argv) > 1 else "start").strip().lower()
    if cmd == "start":
        return _start()
    if cmd == "stop":
        return _stop()
    if cmd == "status":
        return _status()
    if cmd == "serve":
        return _serve()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
