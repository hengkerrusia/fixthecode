#!/usr/bin/env python3
"""Backend origin HTTP/1.1 untuk Lab 9 (stdlib-only).

Membingkai body request berdasarkan Transfer-Encoding (chunked) bila
header itu ada, selain itu berdasarkan Content-Length. Mendukung
pipelining dan keep-alive: setiap request yang utuh langsung diproses
dan responsnya ditulis berurutan di koneksi yang sama.
"""
import os
import socket
import threading

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8000"))

REASONS = {200: "OK", 400: "Bad Request"}


def _read_line(rf):
    line = rf.readline(65536)
    if not line:
        return None
    return line.decode("latin-1").rstrip("\r\n")


def _read_headers(rf):
    headers = {}
    while True:
        line = _read_line(rf)
        if line is None:
            return None
        if line == "":
            break
        if ":" not in line:
            raise ValueError("header buruk")
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers


def _read_exact(rf, n):
    data = b""
    while len(data) < n:
        chunk = rf.read(n - len(data))
        if not chunk:
            raise ValueError("EOF saat membaca body")
        data += chunk
    return data


def _read_chunked(rf):
    body = b""
    while True:
        line = _read_line(rf)
        if line is None:
            raise ValueError("EOF saat membaca chunk")
        size = line.split(";", 1)[0].strip()
        try:
            n = int(size, 16)
        except ValueError:
            raise ValueError("ukuran chunk buruk")
        if n == 0:
            _read_line(rf)
            return body
        body += _read_exact(rf, n)
        _read_line(rf)


def _send(conn, status, body):
    head = ("HTTP/1.1 %d %s\r\nContent-Length: %d\r\n"
            "Content-Type: text/plain\r\nConnection: keep-alive\r\n\r\n"
            % (status, REASONS[status], len(body))).encode("latin-1")
    conn.sendall(head + body)


def _handle(conn):
    conn.settimeout(60)
    rf = conn.makefile("rb")
    try:
        while True:
            line = _read_line(rf)
            if line is None:
                break
            parts = line.split(" ", 2)
            if len(parts) < 2:
                break
            method, target = parts[0], parts[1]
            try:
                headers = _read_headers(rf)
            except ValueError:
                _send(conn, 400, b"bad headers")
                break
            if headers is None:
                break
            te = headers.get("transfer-encoding", "")
            try:
                if "chunked" in te.lower():
                    _read_chunked(rf)
                else:
                    n = int(headers.get("content-length", "0") or "0")
                    _read_exact(rf, n)
            except ValueError:
                try:
                    _send(conn, 400, b"bad body")
                except OSError:
                    pass
                break
            if target == "/":
                _send(conn, 200, b"lab9: ok")
            else:
                _send(conn, 200, ("lab9: echo %s %s"
                                  % (method, target)).encode("latin-1"))
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
    srv.bind((HOST, PORT))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=_handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
