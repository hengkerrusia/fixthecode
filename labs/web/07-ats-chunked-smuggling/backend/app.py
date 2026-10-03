#!/usr/bin/env python3
import os
import socket
import threading

PORT = int(os.environ.get("PORT", "8000"))
ADMIN_SECRET = "ADMIN-SECRET"
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


def send(conn, code, body):
    raw = body.encode("latin-1")
    conn.sendall(("HTTP/1.1 %s\r\nContent-Type: text/plain\r\n"
                  "Content-Length: %d\r\nConnection: close\r\n\r\n"
                  % (code, len(raw))).encode("latin-1") + raw)


def handle(conn):
    try:
        head, rest = recv_head(conn)
        if not head:
            return
        request_line, headers = parse_head(head)
        parts = request_line.split(" ")
        if len(parts) < 2:
            send(conn, "400 Bad Request", "bad request")
            return
        method, path = parts[0], parts[1].split("?", 1)[0]
        if "content-length" in headers:
            try:
                n = int(headers["content-length"])
            except ValueError:
                send(conn, "400 Bad Request", "bad content-length")
                return
            while len(rest) < n:
                chunk = conn.recv(BUF)
                if not chunk:
                    break
                rest += chunk
        if path == "/admin":
            send(conn, "200 OK", "Welcome to the admin panel\n%s\n" % ADMIN_SECRET)
        elif path == "/" or path == "/submit":
            send(conn, "200 OK", "Welcome to the lab\n")
        else:
            send(conn, "404 Not Found", "not found")
    except Exception:
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
        t = threading.Thread(target=handle, args=(conn,), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
