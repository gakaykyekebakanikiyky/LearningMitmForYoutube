import lesson2_tls_dataclasses as lesson2
import lesson3_youtube_spoof as lesson3


def test_load_spoof_rules_reads_file(tmp_path):
    spoof_file = tmp_path / "spoof.list"
    spoof_file.write_text("youtube.com -> www.google.com\n", encoding="utf-8")
    cfg = lesson2.ProxyConfig(spoof_file=spoof_file)
    rules = lesson3.load_spoof_rules(cfg)
    assert rules["youtube.com"] == "www.google.com"


def test_should_spoof_matches_subdomains():
    rules = {"youtube.com": "google.com"}
    assert lesson3.should_spoof("sub.youtube.com", rules) == "google.com"


def test_handle_connect_request_invokes_plain(monkeypatch, tmp_path):
    cfg = lesson2.ProxyConfig(
        ca_cert_file=tmp_path / "ca.crt",
        ca_key_file=tmp_path / "ca.key",
        spoof_file=tmp_path / "spoof.list",
    )
    ca = lesson2.CertificateAuthority.load_or_create(cfg)
    rules = {}
    called = {}

    def fake_plain(client, host, port, socket_factory=None):
        called["plain"] = (host, port)

    monkeypatch.setattr(lesson3, "handle_plain_tunnel", fake_plain)

    class DummySocket:
        def __init__(self):
            self.buffer = []

        def sendall(self, data):
            self.buffer.append(data)

    client = DummySocket()
    lesson3.handle_connect_request(client, "example.com:443", cfg, ca, rules)
    assert called["plain"] == ("example.com", 443)


def test_handle_connect_request_invokes_spoof(monkeypatch, tmp_path):
    cfg = lesson2.ProxyConfig(
        ca_cert_file=tmp_path / "ca.crt",
        ca_key_file=tmp_path / "ca.key",
        spoof_file=tmp_path / "spoof.list",
    )
    ca = lesson2.CertificateAuthority.load_or_create(cfg)
    rules = {"example.com": "target.com"}
    called = {}

    def fake_spoof(client_sock, dest_host, target_host, config, ca_obj):
        called["spoof"] = (dest_host, target_host, ca_obj)

    monkeypatch.setattr(lesson3, "build_spoofed_tunnel", fake_spoof)

    class DummySocket:
        def sendall(self, data):
            pass

    lesson3.handle_connect_request(DummySocket(), "example.com:443", cfg, ca, rules)
    assert called["spoof"][1] == "target.com"

