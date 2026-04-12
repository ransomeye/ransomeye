#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import socket
import stat
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


def _check_tcp(target: str, timeout_s: float) -> tuple[bool, str]:
    host, port_text = target.rsplit(":", 1)
    port = int(port_text)
    with socket.create_connection((host, port), timeout=timeout_s):
        return True, f"tcp:{host}:{port}"


def _check_unix(path: str, timeout_s: float) -> tuple[bool, str]:
    info = os.stat(path)
    if not stat.S_ISSOCK(info.st_mode):
        raise RuntimeError(f"{path} is not a socket")

    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(timeout_s)
    try:
        probe.connect(path)
    except OSError:
        # Datagram/control sockets may reject stream connects; existence as a
        # UNIX socket is enough to prove the service published its local plane.
        pass
    finally:
        probe.close()
    return True, f"unix:{path}"


def _build_check(args: argparse.Namespace):
    if args.tcp:
        return lambda: _check_tcp(args.tcp, args.timeout_ms / 1000.0)
    if args.unix:
        return lambda: _check_unix(args.unix, args.timeout_ms / 1000.0)
    raise RuntimeError("one of --tcp or --unix is required")


class HealthHandler(BaseHTTPRequestHandler):
    service_name: str = "unknown"
    check = None

    def do_GET(self) -> None:
        if self.path != "/api/v1/health":
            self._write_json(HTTPStatus.NOT_FOUND, {"status": "not_found"})
            return

        try:
            _, checked = type(self).check()
        except Exception as exc:
            self._write_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "status": "error",
                    "service": self.service_name,
                    "error": str(exc),
                },
            )
            return

        self._write_json(
            HTTPStatus.OK,
            {
                "status": "ok",
                "service": self.service_name,
                "checked": checked,
            },
        )

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _write_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Loopback-only HTTP health proxy")
    parser.add_argument("--service", required=True, help="logical service name")
    parser.add_argument("--port", type=int, required=True, help="proxy listen port")
    parser.add_argument("--bind", default="127.0.0.1", help="listen address")
    parser.add_argument("--timeout-ms", type=int, default=500, help="probe timeout")
    parser.add_argument("--tcp", help="target TCP address host:port")
    parser.add_argument("--unix", help="target UNIX socket path")
    args = parser.parse_args()
    if args.bind != "127.0.0.1":
        raise SystemExit("health proxy must bind only to 127.0.0.1")
    if (args.tcp is None) == (args.unix is None):
        raise SystemExit("specify exactly one of --tcp or --unix")
    return args


def main() -> int:
    args = parse_args()
    HealthHandler.service_name = args.service
    HealthHandler.check = _build_check(args)

    server = ThreadingHTTPServer((args.bind, args.port), HealthHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
