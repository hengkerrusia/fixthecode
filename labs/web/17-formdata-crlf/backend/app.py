#!/usr/bin/env python3
import os
import re
import socket
import threading

PORT = int(os.environ.get("PORT", "8000"))


def parse_parts(body, boundary):
    delim = ("--" + boundary).encode("latin-1")
    parts = []
    for chunk in body.split(delim)[1:]:
        if chunk.startswith(b"--"):
            break
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        if chunk.endswith(b"\r\n"):
            chunk = chunk[:-2]
        if b"\r\n\r\n" not in chunk:
            continue
        head, content = chunk.split(b"\r\n\r\n", 1)
        headers = []
        for ln in head.decode("latin-1").split("\r\n"):
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers.append((k.strip().lower(), v.strip()))
        parts.append((headers, content))
    return parts


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
            headers = []
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    headers.append((k.strip().lower(), v.strip()))
            cl = 0
            for k, v in headers:
                if k == "content-length":
                    try:
                        cl = int(v)
                    except ValueError:
                        cl = 0
            while len(rest) < cl:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                rest += chunk
            body = rest[:cl]
            buf = rest[cl:]

            if len(parts) < 3 or parts[0] != "POST" or parts[1] != "/store":
                resp = b"not found"
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: %d\r\n"
                             b"Connection: keep-alive\r\n\r\n" % len(resp) + resp)
                continue

            ctype = ""
            for k, v in headers:
                if k == "content-type":
                    ctype = v
            m = re.search(r"boundary=([^\s;]+)", ctype)
            boundary = m.group(1).strip('"') if m else ""
            parsed = parse_parts(body, boundary) if boundary else []

            out = ["upload-ok", "parts: %d" % len(parsed)]
            for i, (phdrs, _) in enumerate(parsed):
                out.append("part %d headers:" % i)
                for k, v in phdrs:
                    out.append(k + ": " + v)
            data = "\n".join(out).encode("latin-1")
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                         b"Content-Length: %d\r\n"
                         b"Connection: keep-alive\r\n\r\n" % len(data) + data)
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
