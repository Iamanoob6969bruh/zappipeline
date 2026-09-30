"""Per-scan egress proxy: only the approved host/port, pinned to its checked IP.

ZAP's HTTP client uses this proxy for HTTP and HTTPS. Redirect destinations and
external page resources are checked on every connection, not just at startup.
This is an application boundary, not an OS sandbox for a compromised scanner.
"""

from __future__ import annotations

import http.client
import select
import socket
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from scope_guard import ScopedTarget


@contextmanager
def scoped_proxy(target: ScopedTarget):
    class Handler(BaseHTTPRequestHandler):
        timeout = 15
        protocol_version = "HTTP/1.0"

        def log_message(self, *_args):
            pass  # URLs can contain credentials; never print them.

        def allowed(self, host, port):
            return host == target.hostname and port == target.port

        def do_CONNECT(self):
            try:
                parsed = urlsplit("https://" + self.path)
                if target.scheme != "https" or not self.allowed(
                    parsed.hostname, parsed.port or 443
                ):
                    self.send_error(403, "Outside approved scan scope")
                    return
                upstream = socket.create_connection((target.ip, target.port), timeout=15)
            except (ValueError, OSError):
                self.send_error(502)
                return
            with upstream:
                self.send_response(200, "Connection established")
                self.end_headers()
                self.wfile.flush()
                # TLS stays end-to-end; the TCP destination never uses DNS again.
                try:
                    while True:
                        ready, _, _ = select.select([self.connection, upstream], [], [], 15)
                        if not ready:
                            break
                        for source in ready:
                            block = source.recv(65536)
                            if not block:
                                return
                            (upstream if source is self.connection else self.connection).sendall(
                                block
                            )
                except OSError:
                    pass
            self.close_connection = True

        def do_GET(self):
            self.forward()

        def do_HEAD(self):
            self.forward()

        def forward(self):
            try:
                parsed = urlsplit(self.path)
                if (
                    target.scheme != "http"
                    or parsed.scheme != "http"
                    or parsed.username is not None
                    or not self.allowed(parsed.hostname, parsed.port or 80)
                ):
                    self.send_error(403, "Outside approved scan scope")
                    return
                # Passive crawling must not submit forms or request bodies.
                if (
                    self.headers.get("Transfer-Encoding")
                    or self.headers.get("Content-Length", "0") != "0"
                ):
                    self.send_error(405)
                    return
                connection = http.client.HTTPConnection(target.ip, target.port, timeout=15)
                hop = {
                    "connection",
                    "proxy-connection",
                    "proxy-authorization",
                    "transfer-encoding",
                    "upgrade",
                    "keep-alive",
                    "host",
                }
                headers = {k: v for k, v in self.headers.items() if k.lower() not in hop}
                headers["Host"] = parsed.netloc
                headers["Connection"] = "close"
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                try:
                    connection.request(self.command, path, headers=headers)
                    response = connection.getresponse()
                    # send_response() would inject the proxy's own Server/Date
                    # headers, which pollute scanner results (ZAP would report the
                    # proxy, not the target). Relay only the upstream's headers.
                    self.send_response_only(response.status)
                    for key, value in response.getheaders():
                        if key.lower() not in hop:
                            self.send_header(key, value)
                    self.end_headers()
                    if self.command != "HEAD":
                        while block := response.read(65536):
                            self.wfile.write(block)
                finally:
                    connection.close()
            except (ValueError, OSError, http.client.HTTPException):
                self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
