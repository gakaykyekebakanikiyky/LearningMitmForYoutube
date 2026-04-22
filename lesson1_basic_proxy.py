"""Урок 1. Базовый CONNECT-прокси без TLS."""

from core import  DEFAULT_BUFFER_SIZE
import socket
import socketserver
import threading
from typing import Callable, Tuple
from core import bridge_streams

# TODO: реализуйте вспомогательные функции, а затем сборку сервера.


def _read_connect_line(client_sock: socket.socket) -> str:
    """Считать первую строку HTTP-запроса CONNECT."""
    a = client_sock.recv(DEFAULT_BUFFER_SIZE)
    if not a:
        print("none")
    a = a.decode("utf-8").split("\r\n")
    return a[0]


def _extract_target(request_line: str) -> str:
    """Вернуть "example.com:443" из строки CONNECT."""
    request_line = request_line.split()
    return request_line[1]


def _send_connection_response(client_sock: socket.socket, status_line: str) -> None:
    """Отправить HTTP-ответ вида "HTTP/1.1 200 Connection Established"."""
    response = f"{status_line}\r\n\r\n"
    client_sock.sendall(response.encode("utf-8"))



def parse_connect_request(request_line: str) -> Tuple[str, int]:
    """Вернуть (host, port), даже если порт не указан явно."""
    if(request_line.startswith("CONNECT")):

        request_line = _extract_target(request_line)

    for i in range(len(request_line)):
        if request_line[i] == ':':
            request_line = request_line.split(request_line[i])
            a1 = request_line[0]
            a2 = request_line[1]
            a2 = int(a2)
            return a1, a2
    return request_line , 443




def open_remote_socket(host: str, port: int, timeout: float = 10.0) -> socket.socket:
    remote_sock = socket.create_connection((host, port), timeout=timeout)
    remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return remote_sock


def handle_plain_tunnel(
    client_sock: socket.socket,
    dest_host: str,
    dest_port: int,
    socket_factory: Callable[[str, int], socket.socket] | None = None,
) -> None:
    """Организовать двунаправленный мост между клиентом и сервером."""
    if socket_factory is None:
        socket_factory = open_remote_socket
    sock = socket_factory(dest_host , dest_port)
    #print(f"мы открываем тунель {dest_host} , мы открываем порт {dest_port}")
    try:
        bridge_streams(client_sock,sock)
    except Exception as e:
        print(e)
    finally:
        sock.close()


def _close_quietly(sock: socket.socket | None) -> None:
    """Вспомогательная функция, которая не кидает исключения при закрытии."""
    raise NotImplementedError


class BasicProxyHandler(socketserver.BaseRequestHandler):
    """Серверный обработчик для тестирования логики из урока."""

    def handle(self) -> None:  # pragma: no cover - реализация нужна студенту
        clientsock = self.request
        try:
            r = _read_connect_line(clientsock)
            if not r[0:7] == "CONNECT":
                _send_connection_response(clientsock, "HTTP/1.1 405 Method Not Allowed")
                return
            h , p = parse_connect_request(r)
            _send_connection_response(clientsock, "HTTP/1.1 200 Connection Established")
            handle_plain_tunnel(clientsock, h , p)
        except Exception as e:
            print(e)
        finally:
            clientsock.close()
        
            


def start_basic_proxy(host: str = "127.0.0.1", port: int = 8080) -> socketserver.ThreadingTCPServer:
    class _Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    server = _Server((host, port), BasicProxyHandler)
    return server
