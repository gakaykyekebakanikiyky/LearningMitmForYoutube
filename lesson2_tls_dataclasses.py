"""Урок 2. Dataclass-конфигурация и TLS-контексты."""

from __future__ import annotations

import os
import tempfile
from asyncio import timeout
from dataclasses import dataclass
from distutils.command.config import config
from lib2to3.fixes.fix_input import context
from pathlib import Path
import socket
import socketserver
import ssl
from socket import create_connection
from ssl import wrap_socket
from typing import Tuple
from wsgiref.simple_server import server_version

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from proxy import bridge_streams, load_or_create_ca_material, generate_cert_for_host
from student.lesson1_basic_proxy import _read_connect_line, _send_connection_response, parse_connect_request, \
    handle_plain_tunnel


@dataclass
class ProxyConfig:
    """Хранит пути к файлам и порт прослушивания прокси."""

    host: str = "127.0.0.1"
    port: int = 8080
    spoof_file: Path = Path("spoof.list")
    ca_cert_file: Path = Path("mitm-ca.crt")
    ca_key_file: Path = Path("mitm-ca.key")
    min_tls_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2


@dataclass
class CertificateAuthority:
    """Загруженный или созданный центр сертификации."""

    cert: x509.Certificate
    key: rsa.RSAPrivateKey

    @classmethod
    def load_or_create(cls, config: ProxyConfig) -> CertificateAuthority:
        """Получить CA из файлов или создать новый."""
        cert , key = load_or_create_ca_material(config.ca_cert_file, config.ca_key_file)
        return cls(cert=cert,key=key)

    def issue_for_host(self, host: str) -> tuple[bytes, bytes]:
        """Генерировать PEM-пары для host."""
        bytes1, bytes2 = generate_cert_for_host(host, self.cert , self.key)
        return bytes1 , bytes2



def _create_server_tls_context(cert_pem: bytes, key_pem: bytes) -> ssl.SSLContext:
    """Контекст, в который мы завертываем клиентский сокет (мы сервер)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_NONE
    cert_file = tempfile.NamedTemporaryFile(delete=False)
    key_file = tempfile.NamedTemporaryFile(delete=False)
    try:
        cert_file.write(cert_pem)
        key_file.write(key_pem)
        cert_file.flush()
        key_file.flush()
        ctx.load_cert_chain(cert_file.name,key_file.name)
    finally:
        cert_file.close()
        key_file.close()
        for path in (cert_file.name, key_file.name):
            try:
                os.unlink(path)
            except OSError:
                pass
    return ctx


def _create_client_tls_context(server_hostname: str, min_version: ssl.TLSVersion) -> ssl.SSLContext:
    """Контекст, которым мы подключаемся к реальному сайту."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = min_version
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    setattr(ctx, "_spoof_hostname", server_hostname)
    return ctx

def build_tls_contexts(host: str, config: ProxyConfig, ca: CertificateAuthority) -> Tuple[ssl.SSLContext, ssl.SSLContext]:
    """Создает пару TLS-контекстов для перехвата."""
    cert_pem, key_pem = ca.issue_for_host(host)
    server_ctx = _create_server_tls_context(cert_pem, key_pem)
    client_ctx = _create_client_tls_context(host, config.min_tls_version)
    return server_ctx, client_ctx



def _tempfile_pair(cert_pem: bytes, key_pem: bytes) -> tuple[str, str]:
    """Подготовьте на диске временные файлы и верните их пути."""
    raise NotImplementedError


def _cleanup_files(*paths: str) -> None:
    """Удалите времен��ые файлы, но не пугайтесь, если их уже нет."""
    raise NotImplementedError


def wrap_client_socket(server_ctx: ssl.SSLContext, client_sock: socket.socket) -> ssl.SSLSocket:
    """Оборачивает клиентский сокет в TLS (мы выступаем сервером)."""
    return server_ctx.wrap_socket(client_sock, server_side=True, suppress_ragged_eofs=True)


def connect_upstream(host: str, port: int, timeout: float = 10.0) -> socket.socket:
    """Создает TCP-соединение до реального сервера."""
    return create_connection((host,port) , timeout=timeout)


def handle_tls_tunnel(client_sock: socket.socket, dest: str, config: ProxyConfig, ca: CertificateAuthority) -> None:
    """Комбинирует wrap_client_socket и connect_upstream для MITM."""
    server, client = build_tls_contexts(host=dest,config=config , ca=ca)
    tls_client = wrap_client_socket(server,client_sock)
    host , port = parse_connect_request(dest)
    socket = connect_upstream(host , port)
    tls_server = client.wrap_socket(socket,server_side=False,suppress_ragged_eofs=True,server_hostname=host)
    try:
        bridge_streams(tls_client,tls_server)
    finally:
        tls_server.close()
        tls_client.close()
        socket.close()







class TLSProxyHandler(socketserver.BaseRequestHandler):  # pragma: no cover
    """Серверный обработчик для проверки урока."""

    config: ProxyConfig
    ca: CertificateAuthority

    def handle(self) -> None:
        clientsock = self.request
        server = self.server
        try:
            r = _read_connect_line(clientsock)
            if not r[0:7] == "CONNECT":
                _send_connection_response(clientsock, "HTTP/1.1 405 Method Not Allowed")
                return
            h, p = parse_connect_request(r)
            _send_connection_response(clientsock, "HTTP/1.1 200 Connection Established")
            handle_tls_tunnel(clientsock,h,config=server.config,ca=server.ca)
        except Exception as e:
            print(e)
        finally:
            clientsock.close()


class _TLSProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, config: ProxyConfig, ca: CertificateAuthority):
        self.config = config
        self.ca = ca
        super().__init__((config.host, config.port), TLSProxyHandler)


def start_tls_proxy(config: ProxyConfig) -> socketserver.ThreadingTCPServer:
    ca = CertificateAuthority.load_or_create(config)
    server = _TLSProxyServer(config, ca)
    return server





