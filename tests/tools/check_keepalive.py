#!/usr/bin/env python3
# Copyright (c) 2026 tangxiangjiang
# SPDX-License-Identifier: MIT

"""Exercise a compiled keepalive_consumer against one real connection per scenario."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import threading


def receive_head(connection: socket.socket) -> bytes:
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        chunk = connection.recv(1)
        if not chunk:
            raise RuntimeError("peer closed before request head completed")
        head.extend(chunk)
        if len(head) > 4096:
            raise RuntimeError("request head exceeds fixture bound")
    return bytes(head)


def scenario(binary: Path, number: int) -> dict:
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)
        port = listener.getsockname()[1]

        def serve() -> None:
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(10)
                    first = receive_head(connection)
                    close = b"Connection: close\r\n" if number == 4 else b""
                    assert first == b"GET /one HTTP/1.1\r\nHost: example.test\r\n" + close + b"\r\n", first
                    response_close = b"Connection: close\r\n" if number == 3 else b""
                    if number == 2:
                        connection.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n0\r\n\r\n")
                    else:
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n" + response_close + b"\r\none")
                    if number in (3, 4):
                        assert not connection.recv(1), "unexpected second request on a closing connection"
                        return
                    second = receive_head(connection)
                    assert second == b"GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n", second
                    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo")
                    assert not connection.recv(1), "unexpected replay or extra request"
            except BaseException as error:
                errors.append(repr(error))

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        result = subprocess.run([str(binary)], env=os.environ | {
            "HTTP_TEST_PORT": str(port), "HTTP_TEST_CASE": str(number)
        }, capture_output=True, text=True, timeout=15)
        worker.join(11)
        if result.returncode or errors or worker.is_alive():
            raise RuntimeError(f"scenario {number}, exit {result.returncode}, peer {errors}, {result.stdout}{result.stderr}")
    return {"scenario": number, "status": "passed"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    results = [scenario(args.binary.resolve(), number) for number in range(1, 7)]
    args.report.write_text(json.dumps({"cases": results}, indent=2) + "\n")
    print(f"HTTP keepalive {len(results)} scenarios passed")


if __name__ == "__main__":
    main()
