#!/usr/bin/env python3
import os
import select
import socket
import threading

PORT = int(os.environ.get("PORT", "80"))
BACKEND_HOST = os.environ.get("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "8000"))
ADMIN_PREFIX = "/admin"
BUF = 65536


def recv_head(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(BUF)
        if not chunk:
            break
        data += chunk
        if len(data) > 1 << 20:
            break
    head, _, rest = data.partition(b"\r\n\r\n")
    return head, rest


def parse_head(head):
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("latin-1") if lines else ""
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return request_line, headers


def flat_headers(request_line, headers):
    lines = [request_line]
    for k, v in headers.items():
        lines.append("%s: %s" % (k, v))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def send_status(conn, code, body):
    raw = body.encode("latin-1")
    conn.sendall(("HTTP/1.1 %s\r\nContent-Type: text/plain\r\n"
                  "Content-Length: %d\r\nConnection: close\r\n\r\n"
                  % (code, len(raw))).encode("latin-1") + raw)


def is_upgrade(headers):
    tokens = [t.strip() for t in headers.get("connection", "").lower().split(",")]
    return "upgrade" in tokens and headers.get("upgrade", "").lower() == "h2c"


def tunnel(a, b):
    pair = [a, b]
    while True:
        ready, _, _ = select.select(pair, [], [], 60)
        if not ready:
            return
        for s in ready:
            try:
                data = s.recv(BUF)
            except OSError:
                return
            if not data:
                return
            try:
                (b if s is a else a).sendall(data)
            except OSError:
                return


def handle(conn):
    up = None
    try:
        head, rest = recv_head(conn)
        if not head:
            return
        request_line, headers = parse_head(head)
        parts = request_line.split(" ")
        if len(parts) < 2:
            send_status(conn, "400 Bad Request", "bad request")
            return
        path = parts[1].split("?", 1)[0]
        if path.startswith(ADMIN_PREFIX):
            send_status(conn, "403 Forbidden", "Forbidden")
            return
        upgrade = is_upgrade(headers)
        if not upgrade:
            headers["connection"] = "close"
        up = socket.create_connection((BACKEND_HOST, BACKEND_PORT), timeout=10)
        up.sendall(flat_headers(request_line, headers) + rest)
        bhead, brest = recv_head(up)
        if not bhead:
            return
        conn.sendall(bhead + b"\r\n\r\n" + brest)
        status_line = bhead.split(b"\r\n", 1)[0]
        if upgrade and b" 101 " in status_line:
            tunnel(conn, up)
            return
        while True:
            chunk = up.recv(BUF)
            if not chunk:
                break
            conn.sendall(chunk)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
        if up is not None:
            try:
                up.close()
            except OSError:
                pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        t = threading.Thread(target=handle, args=(conn,), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
