"""Network egress monitor — proof that data physically left the box.

Stands up a throwaway local HTTP listener on an ephemeral port and records every
POST body it receives. The vuln lab's `http_post` sink sends to this listener, so
the oracle can confirm the canary secret actually crossed the network — a real
outbound request, not just a write to a local file. Stdlib only.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        self.server.captured_bodies.append(body)  # type: ignore[attr-defined]
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # silence the default stderr logging
        pass


class EgressMonitor:
    def __init__(self):
        self.httpd: HTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.port: int | None = None

    def start(self) -> "EgressMonitor":
        self.httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.captured_bodies = []  # type: ignore[attr-defined]
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/exfil"

    def captured(self, needle: str) -> bool:
        if not self.httpd:
            return False
        return any(needle in body for body in self.httpd.captured_bodies)  # type: ignore[attr-defined]

    def stop(self) -> None:
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
