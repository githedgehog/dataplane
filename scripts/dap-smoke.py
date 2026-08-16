#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

"""Check that the dev-debugger image really launches a debuggee over DAP.

The image only listens; in remote-DAP mode bugstalker ignores the debuggee
named on its command line and waits for the client's `launch` request to
supply `arguments.program`.  Connecting therefore proves nothing, which is
how the image shipped with a documented invocation that could not work.

Exits non-zero unless a launch actually produces a running process.
"""

import json
import socket
import sys
import time

TIMEOUT = 60.0


def send(sock: socket.socket, seq: int, command: str, arguments: dict) -> None:
    body = json.dumps(
        {"seq": seq, "type": "request", "command": command, "arguments": arguments}
    ).encode()
    sock.sendall(b"Content-Length: %d\r\n\r\n" % len(body) + body)


def messages(sock: socket.socket, seconds: float):
    """Yield DAP messages until the socket goes quiet for `seconds`."""
    sock.settimeout(0.5)
    buf = b""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            return
        buf += chunk
        while b"\r\n\r\n" in buf:
            head, rest = buf.split(b"\r\n\r\n", 1)
            fields = {}
            for line in head.decode(errors="replace").strip().splitlines():
                key, sep, value = line.partition(":")
                if sep:
                    fields[key.strip().lower()] = value.strip()
            if "content-length" not in fields:
                # Not a header we understand; drop it rather than wedging.
                buf = rest
                continue
            length = int(fields["content-length"])
            if len(rest) < length:
                break
            yield json.loads(rest[:length])
            buf = rest[length:]


def connect(port: int) -> socket.socket:
    """Wait for the container's listener rather than assuming it is up."""
    deadline = time.monotonic() + TIMEOUT
    while True:
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=5)
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)


def main() -> int:
    port, program = int(sys.argv[1]), sys.argv[2]
    sock = connect(port)

    send(sock, 1, "initialize", {"adapterID": "smoke", "linesStartAt1": True})
    if not any(
        m.get("command") == "initialize" and m.get("success") for m in messages(sock, 10)
    ):
        print("::error::adapter never answered `initialize`", file=sys.stderr)
        return 1

    send(sock, 2, "launch", {"program": program, "args": []})
    launched, pid = False, None
    for message in messages(sock, 20):
        if message.get("type") == "response" and message.get("command") == "launch":
            if not message.get("success"):
                print(
                    f"::error::launch rejected: {message.get('message')}",
                    file=sys.stderr,
                )
                return 1
            launched = True
        elif message.get("event") == "process":
            pid = message.get("body", {}).get("systemProcessId")

    if not launched:
        print("::error::adapter never answered `launch`", file=sys.stderr)
        return 1
    if pid is None:
        # A successful launch that starts nothing is the failure this guards.
        print("::error::launch succeeded but no process event arrived", file=sys.stderr)
        return 1

    print(f"dev-debugger: launched {program} as pid {pid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
