import logging
import os
import socket
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEFAULT_BUFFER_SIZE = 65536
logger = logging.getLogger(__name__)


def bridge_streams(client_sock: socket.socket, server_sock: socket.socket) -> None:
    """Прокачивает данные между двумя сокетами в обе стороны."""

    def _forward(src: socket.socket, dst: socket.socket, label: str) -> None:
        try:
            while True:
                chunk = src.recv(DEFAULT_BUFFER_SIZE)
                if not chunk:
                    break
                dst.sendall(chunk)
        except Exception as exc:  # pragma: no cover - дефенсивный лог
            logger.debug("%s поток закрыт: %s", label, exc)
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    left = threading.Thread(target=_forward, args=(client_sock, server_sock, "C→S"), daemon=True)
    right = threading.Thread(target=_forward, args=(server_sock, client_sock, "S→C"), daemon=True)
    left.start()
    right.start()
    left.join()
    right.join()


def ensure_spoof_file(path: Path) -> None:
    """Создает файл с дефолтными правилами, если его еще нет."""
    if path.exists():
        return
    path.write_text(
        "# origin -> spoof\n"
        "youtube.com -> www.google.com\n"
        "ytimg.com -> www.google.com\n"
        "googlevideo.com -> c.drive.google.com\n",
        encoding="utf-8",
    )


def load_spoof_map(path: Path) -> Dict[str, str]:
    """Возвращает словарь правил подмены доменов."""
    ensure_spoof_file(path)
    mapping: Dict[str, str] = {}
    for line_num, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "->" not in line:
            logger.warning("Строка %s пропущена: %s", line_num, line)
            continue
        origin, spoof = (part.strip().lower() for part in line.split("->", 1))
        mapping[origin] = spoof
    return mapping


def get_spoof_target(host: str, mapping: Dict[str, str]) -> str | None:
    """Возвращает домен для спуфинга, если он определен."""
    hostname = host.split(":")[0].lower()
    for origin, spoof in mapping.items():
        if hostname == origin or hostname.endswith("." + origin):
            print("hooray")
            return spoof
    return None


def load_or_create_ca_material(cert_path: Path, key_path: Path) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Загружает существующий CA или создает новый."""
    if cert_path.exists() and key_path.exists():
        with cert_path.open("rb") as cert_file:
            cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
        with key_path.open("rb") as key_file:
            key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        return cert, key

    print("ca new creating...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SNI Spoof Proxy"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SNI Spoof CA"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert, key


def generate_cert_for_host(host: str, ca_cert: x509.Certificate, ca_key: rsa.RSAPrivateKey) -> Tuple[bytes, bytes]:
    """Создает короткоживущий сертификат для конкретного домена."""
    clean_host = host.split(":")[0].lower()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, clean_host)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(clean_host)]), critical=False)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem

