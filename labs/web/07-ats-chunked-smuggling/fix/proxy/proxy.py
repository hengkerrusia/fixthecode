#!/usr/bin/env python3
import os
import socket
import threading

import chunked

PORT = int(os.environ.get("PORT", "80"))
BACKEND_HOST = os.environ.get("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "8000"))
BUF = 65536
MAX_HEAD = 1 << 20


class Conn:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _fill(self):
        data = self.sock.recv(BUF)
        if data:
            self.buf += data
        return data

    def read_head(self):
        while b"\r\n\r\n" not in self.buf:
            if not self._fill():
                return None, None
            if len(self.buf) > MAX_HEAD:
                return None, None
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        self.buf = rest
        return head, True

    def read_exactly(self, n):
        while len(self.buf) < n:
            if not self._fill():
                return None
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_chunked_body(self):
        while True:
            try:
                body, consumed = chunked.dechunk(self.buf)
            except chunked.Truncated:
                pass
            except ValueError:
                return None
            else:
                self.buf = self.buf[consumed:]
                return body
            if not self._fill():
                return None

    def sendall(self, data):
        self.sock.sendall(data)


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


def handle(conn):
    up = None
    try:
        while True:
            head, ok = conn.read_head()
            if not ok:
                return
            request_line, headers = parse_head(head)
            parts = request_line.split(" ")
            if len(parts) < 2:
                send_status(conn, "400 Bad Request", "bad request")
                return
            te = headers.get("transfer-encoding", "")
            if "chunked" in te.lower():
                body = conn.read_chunked_body()
                if body is None:
                    send_status(conn, "400 Bad Request", "malformed chunked body")
                    return
                headers.pop("transfer-encoding", None)
                headers["content-length"] = str(len(body))
            elif "content-length" in headers:
                try:
                    n = int(headers["content-length"])
                except ValueError:
                    send_status(conn, "400 Bad Request", "bad content-length")
                    return
                body = conn.read_exactly(n)
                if body is None:
                    return
            else:
                body = b""
            headers["connection"] = "close"
            up = socket.create_connection((BACKEND_HOST, BACKEND_PORT), timeout=10)
            up.sendall(flat_headers(request_line, headers) + body)
            resp = b""
            while True:
                data = up.recv(BUF)
                if not data:
                    break
                resp += data
            conn.sendall(resp)
            up.close()
            up = None
    except Exception:
        pass
    finally:
        try:
            conn.sock.close()
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
        sock, _ = srv.accept()
        sock.settimeout(10)
        t = threading.Thread(target=handle, args=(Conn(sock),), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
