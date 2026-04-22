"""Урок 3. Логика спуфинга YouTube и финальный прокси."""

from __future__ import annotations

import socket
import socketserver

from core import bridge_streams, get_spoof_target, load_spoof_map
from lesson1_basic_proxy import _read_connect_line, _send_connection_response, parse_connect_request ,_extract_target, handle_plain_tunnel
from typing import Dict

from lesson2_tls_dataclasses import CertificateAuthority, ProxyConfig, build_tls_contexts, wrap_client_socket, \
    connect_upstream


def load_spoof_rules(config: ProxyConfig) -> Dict[str, str]:
    """Считать правила из spoof.list и вернуть словарь."""
    # d = {}
    # with open('spoof.list', 'r', encoding='utf-8') as file:
    #     for i in file:
    #         i = i.strip()
    #         first, second = i.split(' -> ')
    #         d[first] = second
    #
    #     return d
    return load_spoof_map(config.spoof_file)


def should_spoof(host: str, rules: Dict[str, str]) -> str | None:
    """Вернуть целевой домен, если host нужно подменить."""
    # host = host.split(":")
    # name = host[0].lower()
    # for i , a in rules.items():
    #     if i == name:
    #         print("all is ok")
    #         return a
    # return None
    return get_spoof_target(host,rules)


def build_spoofed_tunnel(
    client_sock: socket.socket,
    dest_host: str,
    target_host: str,
    config: ProxyConfig,
    ca: CertificateAuthority,
) -> None:
    """Обработать TLS-туннель с подменой SNI."""
    server, client = build_tls_contexts(host=dest_host,config=config , ca=ca)
    tls_client = wrap_client_socket(server,client_sock)
    host , port = parse_connect_request(dest_host)
    socket1 = connect_upstream(host , port)
    tls_server = client.wrap_socket(socket1,server_side=False,suppress_ragged_eofs=True,server_hostname=target_host)
    try:
        bridge_streams(tls_client,tls_server)
    finally:
        tls_server.close()
        tls_client.close()
        socket1.close()



def handle_connect_request(
    client_sock: socket.socket,
    dest: str,
    config: ProxyConfig,
    ca: CertificateAuthority,
    rules: Dict[str, str],
) -> None:
    """Выбрать обычный или спуфнутый сценарий."""
    flag = should_spoof(dest , rules)
    host, port = parse_connect_request(dest)
    print(host, port)
    if flag:
        #print("dads")
        build_spoofed_tunnel(client_sock,dest,flag,config,ca)
        print("перенаправляем из " ,dest,"в",flag)
    else:
        handle_plain_tunnel(client_sock, host, port)





class _SpoofingHandler(socketserver.BaseRequestHandler):

    def handle(self) -> None:
        cs = self.request
        sr = self.server
        try:
            r = _read_connect_line(cs)
            if not r[0:7] == "CONNECT":
                _send_connection_response(cs, "HTTP/1.1 405 Method Not Allowed")
                return
            h, p = parse_connect_request(r)

            _send_connection_response(cs, "HTTP/1.1 200 Connection Established")
            handle_connect_request(cs,_extract_target(r), sr.config , sr.ca, sr.rules )

        except Exception as e:
            print(e)
        finally:
            cs.close()


class SpoofingProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, config: ProxyConfig, ca: CertificateAuthority, rules: Dict[str, str]):
        self.config = config
        self.ca = ca
        self.rules = rules
        super().__init__((config.host, config.port), _SpoofingHandler)


def start_spoofing_proxy(config: ProxyConfig) -> SpoofingProxyServer:
    ca = CertificateAuthority.load_or_create(config)
    print("ca created")
    rules = load_spoof_rules(config)
    server = SpoofingProxyServer(config, ca, rules)
    return server


