#!/usr/bin/env python3
"""Backend HTTP/1.1 untuk Lab 10.

Menghormati Content-Length secara ketat (sisi "CL" dari 0.CL).
Untuk path gadget dengan Expect: 100-continue, backend mengirim
respons lebih awal TANPA menunggu body, lalu menguras (drain) body
demi menjaga sinkronisasi koneksi keep-alive — perilaku umum
server nyata (mis. nginx menyajikan file statis).
"""
import os
import socket
import threading

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8000"))
GADGET_PATH = "/static/logo.png"
TIMEOUT = 10


def send(conn, status, body):
    reason = {200: "OK", 400: "Bad Request"}.get(status, "OK")
    head = ("HTTP/1.1 %d %s\r\nContent-Length: %d\r\n"
            "Content-Type: text/plain\r\n\r\n"
            % (status, reason, len(body)))
    conn.sendall(head.encode("latin-1") + body)


def send_100(conn):
    conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")


def recv_exact(rf, n):
    data = b""
    while len(data) < n:
        chunk = rf.read(n - len(data))
        if not chunk:
            raise ConnectionError("EOF")
        data += chunk
    return data


def handle(conn):
    conn.settimeout(TIMEOUT)
    rf = conn.makefile("rb")
    try:
        while True:
            line = rf.readline(65536)
            if not line:
                break
            parts = line.decode("latin-1").rstrip("\r\n").split(" ", 2)
            if len(parts) < 2:
                send(conn, 400, b"bad request")
                break
            method, path = parts[0], parts[1]
            headers = {}
            while True:
                h = rf.readline(65536)
                if not h:
                    raise ConnectionError("EOF")
                hs = h.decode("latin-1").rstrip("\r\n")
                if hs == "":
                    break
                if ":" in hs:
                    k, v = hs.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            try:
                cl = int(headers.get("content-length", "0") or "0")
            except ValueError:
                cl = 0
            expect = headers.get("expect", "").lower() == "100-continue"

            if expect and path == GADGET_PATH:
                # Early-response gadget: balas 200 SEKARANG tanpa menunggu
                # body, lalu kuras body demi sinkronisasi keep-alive.
                send(conn, 200, b"lab10: early")
                try:
                    recv_exact(rf, cl)
                except (OSError, ConnectionError):
                    break
                continue
            if expect:
                send_100(conn)
                try:
                    body = recv_exact(rf, cl) if cl else b""
                except (OSError, ConnectionError):
                    break
                send(conn, 200, b"lab10: " + path.encode("latin-1"))
                continue
            try:
                body = recv_exact(rf, cl) if cl else b""
            except (OSError, ConnectionError):
                break
            if path == "/":
                send(conn, 200, b"lab10: ok")
            elif path == "/echo" and method == "POST":
                send(conn, 200, b"lab10: echo:" + body)
            else:
                send(conn, 200, b"lab10: " + path.encode("latin-1"))
    except (OSError, ConnectionError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
