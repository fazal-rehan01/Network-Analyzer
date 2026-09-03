"""A minimal loopback HTTP test server used as a safe, controlled target."""
from __future__ import annotations

import http.server
import socketserver
import threading


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # noqa: D401
        return


class LocalHttpServer:
    """Runs a tiny HTTP server bound to 127.0.0.1 for simulation purposes."""

    def __init__(self, port: int = 8080) -> None:
        self.port = port
        self._httpd: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        if self.running:
            return True
        try:
            self._httpd = socketserver.TCPServer(("127.0.0.1", self.port), _Handler)
        except OSError:
            return False
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True, name="local-http")
        self._thread.start()
        return True

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
