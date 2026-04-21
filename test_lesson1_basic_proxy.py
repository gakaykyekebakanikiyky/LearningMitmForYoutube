import socket

import pytest

import lesson1_basic_proxy as lesson1


def test_parse_connect_request_with_port():
    host, port = lesson1.parse_connect_request("CONNECT example.com:4443 HTTP/1.1")
    assert (host, port) == ("example.com", 4443)


def test_parse_connect_request_without_port():
    host, port = lesson1.parse_connect_request("CONNECT youtube.com HTTP/1.1")
    assert (host, port) == ("youtube.com", 443)


def test_read_connect_line_returns_first_line():
    server, client = socket.socketpair()
    try:
        client.sendall(b"CONNECT test:443 HTTP/1.1\r\nHost: test\r\n\r\n")
        line = lesson1._read_connect_line(server)
        assert line == "CONNECT test:443 HTTP/1.1"
    finally:
        server.close()
        client.close()


def test_handle_plain_tunnel_uses_bridge(monkeypatch):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    class DummyRemote:
        def close(self):
            pass

    remote = DummyRemote()
    called = {}

    def fake_factory(host, port):
        called["target"] = (host, port)
        return remote

    def fake_bridge(client, server):
        called["bridge"] = (client, server)

    monkeypatch.setattr(lesson1, "bridge_streams", fake_bridge)

    try:
        lesson1.handle_plain_tunnel(client_sock, "example.com", 443, socket_factory=fake_factory)
    finally:
        client_sock.close()

    assert called["target"] == ("example.com", 443)
    assert called["bridge"] == (client_sock, remote)

