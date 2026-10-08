#!/usr/bin/env python3
import os
import socket
import threading
from urllib.parse import urlsplit, parse_qs

PORT = int(os.environ.get("PORT", "8000"))


def _send(conn, code, body):
    data = body if isinstance(body, bytes) else body.encode("latin-1")
    conn.sendall(b"HTTP/1.1 " + code + b"\r\nContent-Length: %d\r\n"
                 b"Connection: keep-alive\r\n\r\n" % len(data) + data)


def handle(conn):
    buf = b""
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
            head, rest = buf.split(b"\r\n\r\n", 1)
            lines = head.decode("latin-1").split("\r\n")
            parts = lines[0].split(" ")
            cl = 0
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    if k.strip().lower() == "content-length":
                        try:
                            cl = int(v.strip())
                        except ValueError:
                            cl = 0
            while len(rest) < cl:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                rest += chunk
            rest = rest[cl:]
            if len(parts) < 3 or not parts[0]:
                _send(conn, b"400 Bad Request", b"bad request")
                buf = rest
                continue
            u = urlsplit(parts[1])
            if u.path == "/echo":
                m = parse_qs(u.query).get("m", [""])[0]
                _send(conn, b"200 OK", "echo:" + m)
            elif u.path == "/":
                _send(conn, b"200 OK", b"backend ok")
            else:
                _send(conn, b"404 Not Found", b"not found")
            buf = rest
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
