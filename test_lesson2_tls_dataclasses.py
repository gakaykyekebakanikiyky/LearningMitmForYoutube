import ssl

import lesson2_tls_dataclasses as lesson2


def test_ca_creation(tmp_path):
    cfg = lesson2.ProxyConfig(
        ca_cert_file=tmp_path / "ca.crt",
        ca_key_file=tmp_path / "ca.key",
        spoof_file=tmp_path / "spoof.list",
    )
    ca = lesson2.CertificateAuthority.load_or_create(cfg)
    assert ca.cert.subject is not None
    assert cfg.ca_cert_file.exists()
    assert cfg.ca_key_file.exists()


def test_issue_for_host_returns_pem(tmp_path):
    cfg = lesson2.ProxyConfig(
        ca_cert_file=tmp_path / "ca.crt",
        ca_key_file=tmp_path / "ca.key",
        spoof_file=tmp_path / "spoof.list",
    )
    ca = lesson2.CertificateAuthority.load_or_create(cfg)
    cert_pem, key_pem = ca.issue_for_host("example.com")
    assert b"BEGIN CERTIFICATE" in cert_pem
    assert b"BEGIN RSA PRIVATE KEY" in key_pem


def test_build_tls_contexts_sets_properties(tmp_path):
    cfg = lesson2.ProxyConfig(
        ca_cert_file=tmp_path / "ca.crt",
        ca_key_file=tmp_path / "ca.key",
        spoof_file=tmp_path / "spoof.list",
        min_tls_version=ssl.TLSVersion.TLSv1_2,
    )
    ca = lesson2.CertificateAuthority.load_or_create(cfg)
    server_ctx, client_ctx = lesson2.build_tls_contexts("example.com", cfg, ca)
    assert server_ctx.verify_mode == ssl.CERT_NONE
    assert client_ctx.verify_mode == ssl.CERT_REQUIRED
    assert client_ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert getattr(client_ctx, "_spoof_hostname") == "example.com"

