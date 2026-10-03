#!/usr/bin/env python3
"""Backend origin untuk Lab 8 (HTTP/1.1, stdlib-only).

Server HTTP kecil: membingkai body request berdasarkan
Transfer-Encoding bila header itu ada, selain itu Content-Length.
Mendukung pipelining dan keep-alive di satu koneksi.
"""
import socket
import threading
from urllib.parse import urlsplit, parse_qs

HOST = "0.0.0.0"
PORT = int(__import__("os").environ.get("PORT", "8000"))

REASONS = {200: "OK", 400: "Bad Request", 404: "Not Found"}


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
            raise ValueError("EOF saat membaca ukuran chunk")
        try:
            size = int(line.split(";", 1)[0].strip(), 16)
        except ValueError:
            raise ValueError("ukuran chunk buruk")
        if size < 0:
            raise ValueError("ukuran chunk negatif")
        if size == 0:
            while True:
                trail = _read_line(rf)
                if trail is None:
                    raise ValueError("EOF di trailer chunk")
                if trail == "":
                    return body
        body += _read_exact(rf, size)
        if rf.read(2) != b"\r\n":
            raise ValueError("chunk tidak diakhiri CRLF")


def _parse_request(rf):
    line = _read_line(rf)
    if line is None:
        return None
    parts = line.split()
    if len(parts) != 3:
        raise ValueError("request line buruk")
    method, target, _version = parts
    headers = _read_headers(rf)
    if headers is None:
        return None
    te = headers.get("transfer-encoding", "")
    tokens = [t.strip().lower() for t in te.split(",") if t.strip()]
    if "chunked" in tokens:
        body = _read_chunked(rf)
    elif "content-length" in headers:
        try:
            n = int(headers["content-length"])
        except ValueError:
            raise ValueError("content-length buruk")
        if n < 0:
            raise ValueError("content-length negatif")
        body = _read_exact(rf, n) if n else b""
    else:
        body = b""
    return method, target, headers, body


def _respond(conn, status, body, content_type="text/html; charset=utf-8",
             keep_alive=True):
    reason = REASONS.get(status, "")
    if isinstance(body, str):
        body = body.encode("utf-8")
    head = (
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: %s\r\n"
        "\r\n"
    ) % (status, reason, content_type, len(body),
         "keep-alive" if keep_alive else "close")
    conn.sendall(head.encode("latin-1") + body)


PAGE_HOME = """<!doctype html>
<html><head><title>Contoh Toko</title></head><body>
<h1>Contoh Toko</h1>
<p>Selamat datang di toko contoh.</p>
<p><a href="/signin">Masuk</a></p>
</body></html>"""


def _page_signin(msg):
    notice = "<p>Silakan masuk untuk melanjutkan.</p>"
    if msg:
        notice = "<p>%s</p>" % msg
    return """<!doctype html>
<html><head><title>Masuk</title></head><body>
<h1>Masuk</h1>
%s
<form method="post" action="/signin">
<input name="user" placeholder="nama pengguna">
<button type="submit">Masuk</button>
</form>
</body></html>""" % notice


def _handle(conn):
    rf = conn.makefile("rb")
    try:
        while True:
            try:
                req = _parse_request(rf)
            except ValueError:
                _respond(conn, 400, "bad request", "text/plain",
                         keep_alive=False)
                break
            if req is None:
                break
            method, target, headers, _body = req
            keep_alive = headers.get("connection", "").lower() != "close"
            path = urlsplit(target).path
            if method == "GET" and path == "/":
                _respond(conn, 200, PAGE_HOME, keep_alive=keep_alive)
            elif path == "/signin" and method in ("GET", "POST"):
                msg = None
                if method == "GET":
                    qs = parse_qs(urlsplit(target).query,
                                  keep_blank_values=True)
                    vals = qs.get("msg")
                    if vals:
                        msg = vals[0]
                _respond(conn, 200, _page_signin(msg), keep_alive=keep_alive)
            elif method == "POST" and path == "/":
                _respond(conn, 200, "OK", "text/plain", keep_alive=keep_alive)
            else:
                _respond(conn, 404, "not found", "text/plain",
                         keep_alive=keep_alive)
            if not keep_alive:
                break
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(128)
    while True:
        conn, _addr = srv.accept()
        t = threading.Thread(target=_handle, args=(conn,), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
