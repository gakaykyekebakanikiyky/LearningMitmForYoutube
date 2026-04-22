"""Простой CLI для запуска каждого чекпоинта."""

from __future__ import annotations

import argparse
import signal
from pathlib import Path

from core import load_or_create_ca_material
import lesson1_basic_proxy as lesson1
import lesson2_tls_dataclasses as lesson2
import lesson3_youtube_spoof as lesson3


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Учебный прокси по урокам")
    parser.add_argument("--lesson", type=int, choices=[1, 2, 3], default=3, help="Какой этап запустить")
    parser.add_argument("--host", default="127.0.0.1", help="Адрес прослушивания")
    parser.add_argument("--port", type=int, default=8080, help="Порт прослушивания")
    parser.add_argument("--spoof-file", type=Path, default=Path("spoof.list"), help="Путь к spoof.list")
    parser.add_argument("--ca-cert", type=Path, default=Path("mitm-ca.crt"), help="CA сертификат")
    parser.add_argument("--ca-key", type=Path, default=Path("mitm-ca.key"), help="CA приватный ключ")
    return parser.parse_args()


def _serve(server , port="8080") -> None:
    stop = False

    def _signal_handler(signum, frame):
        nonlocal stop
        stop = True
        server.shutdown()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    with server:
        print("Сервер запущен, Ctrl+C для остановки.")
        print("Сервер запущен на порте:",port)
        server.serve_forever()
    if stop:
        print("Остановлено пользователем.")


def main() -> None:
    args = _parse_args()
    if args.lesson == 1:
        server = lesson1.start_basic_proxy(host=args.host, port=args.port)
    else:
        config = lesson2.ProxyConfig(
            host=args.host,
            port=args.port,
            spoof_file=args.spoof_file,
            ca_cert_file=args.ca_cert,
            ca_key_file=args.ca_key,
        )
        load_or_create_ca_material(config.ca_cert_file,config.ca_key_file)
        if args.lesson == 2:
            server = lesson2.start_tls_proxy(config)
        else:
            server = lesson3.start_spoofing_proxy(config)
    _serve(server , port=args.port)



if __name__ == "__main__":
    main()

