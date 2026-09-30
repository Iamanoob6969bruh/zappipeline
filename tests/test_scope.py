import asyncio
import http.client
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import runner
from scope_guard import ScopeViolationError, resolve_target, validate_target_scope
from scope_proxy import scoped_proxy


@pytest.mark.parametrize(
    "url", ["http://127.0.0.1:3000", "https://[::1]:8443/a", "http://localhost"]
)
def test_local_scope(url):
    assert validate_target_scope(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "http://8.8.8.8",
        "https://192.168.1.4",
        "file:///etc/passwd",
        "localhost:3000",
        "http://user:pass@localhost",
        "http://localhost/#fragment",
        "http://localhost:99999",
        "http://local host",
        "http://localhost\\@8.8.8.8",
    ],
)
def test_bad_scope(url):
    with pytest.raises(ScopeViolationError):
        validate_target_scope(url)


def test_mixed_dns_even_for_localhost(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", 80, 0, 0)),
        ],
    )
    with pytest.raises(ScopeViolationError):
        resolve_target("http://localhost")


def test_refusal_precedes_every_subprocess(monkeypatch, tmp_path):
    calls = []

    async def execute(*args, **kwargs):
        calls.append(args)
        raise AssertionError("Must not execute")

    monkeypatch.setattr(runner, "_exec", execute)
    with pytest.raises(ScopeViolationError):
        asyncio.run(runner.run_scanners(str(tmp_path), "http://8.8.8.8"))
    assert calls == []


def test_proxy_pins_dns_and_refuses_other_origins(monkeypatch):
    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://8.8.8.8/escape")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = resolve_target(f"http://localhost:{server.server_port}")
    try:
        with scoped_proxy(target) as port:
            original = socket.getaddrinfo

            def resolve(host, *args, **kwargs):
                assert host != "localhost", (
                    "Validated hostname must never be resolved a second time"
                )
                return original(host, *args, **kwargs)

            monkeypatch.setattr(socket, "getaddrinfo", resolve)
            for url, expected in [
                (target.url, 302),
                ("http://8.8.8.8/escape", 403),
                ("http://localhost:1/", 403),
            ]:
                client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                client.request("GET", url)
                assert client.getresponse().status == expected
                client.close()
            client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            client.request("CONNECT", "8.8.8.8:443")
            assert client.getresponse().status == 403
            client.close()
    finally:
        server.shutdown()
        server.server_close()


def test_proxy_relays_only_target_headers_no_python_banner():
    """Regression: the proxy must not add its own BaseHTTP/Python Server header."""
    import threading
    import urllib.request
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from scope_guard import ScopedTarget
    from scope_proxy import scoped_proxy

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response_only(200)
            self.send_header("Server", "nginx/1.30.4")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        tport = server.server_port
        target = ScopedTarget(
            url=f"http://127.0.0.1:{tport}",
            hostname="127.0.0.1",
            ip="127.0.0.1",
            port=tport,
            scheme="http",
        )
        with scoped_proxy(target) as pport:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{pport}"})
            )
            resp = opener.open(f"http://127.0.0.1:{tport}/", timeout=10)
            servers = resp.headers.get_all("Server") or []
    finally:
        server.shutdown()
    assert servers == ["nginx/1.30.4"], servers
    assert not any("Python" in s or "BaseHTTP" in s for s in servers)
