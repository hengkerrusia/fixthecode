#!/usr/bin/env python3
"""
mid/proxy.py — Proxy penerus antara frontend dan backend.

Menerima request HTTP dari frontend, meneruskannya ke upstream (app),
lalu mengembalikan responsenya ke klien. Sebelum diteruskan, proxy
menangani header Connection dan X-Forwarded-For.

Proxy ini melayani satu request per koneksi (Connection: close ke dua arah).
"""
import os
import socket
import threading

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
UPSTREAM_HOST = os.environ.get("UPSTREAM_HOST", "app")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "8000"))
BUF = 65536


def recv_until_headers(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(BUF)
        if not chunk:
            break
        data += chunk
        if len(data) > 1 << 16:  # batasi ukuran header
            break
    return data


def handle(client):
    try:
        peer_ip = client.getpeername()[0]
        raw = recv_until_headers(client)
        if b"\r\n\r\n" not in raw:
            return
        head, _, rest = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        request_line = lines[0].decode("latin-1")
        headers = []
        for line in lines[1:]:
            if b":" in line:
                name, value = line.split(b":", 1)
                headers.append([name.decode("latin-1").strip(),
                                value.decode("latin-1").strip()])

        # Kumpulkan token dari header Connection.
        hop_by_hop = set()
        for name, value in headers:
            if name.lower() == "connection":
                for token in value.split(","):
                    token = token.strip().lower()
                    if token:
                        hop_by_hop.add(token)

        # Hapus header yang terdaftar + header Connection sendiri.
        forwarded = []
        for name, value in headers:
            lname = name.lower()
            if lname == "connection":
                continue
            if lname in hop_by_hop:
                continue
            forwarded.append((name, value))

        # X-Forwarded-For: set jika tidak ada, append IP peer jika ada.
        xff_idx = next(
            (i for i, (n, _) in enumerate(forwarded)
             if n.lower() == "x-forwarded-for"),
            None,
        )
        if xff_idx is None:
            forwarded.append(("X-Forwarded-For", peer_ip))
        else:
            name, value = forwarded[xff_idx]
            forwarded[xff_idx] = (name, "%s, %s" % (value, peer_ip))

        # Body: hanya Content-Length (cukup untuk lab ini).
        body = rest
        content_length = 0
        for name, value in forwarded:
            if name.lower() == "content-length":
                try:
                    content_length = int(value)
                except ValueError:
                    content_length = 0
        while len(body) < content_length:
            chunk = client.recv(BUF)
            if not chunk:
                break
            body += chunk
        body = body[:content_length]

        # Teruskan ke upstream; baca respons sampai EOF (Connection: close).
        out_lines = [request_line]
        for name, value in forwarded:
            out_lines.append("%s: %s" % (name, value))
        out_lines.append("Connection: close")
        out = ("\r\n".join(out_lines) + "\r\n\r\n").encode("latin-1") + body

        up = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=10)
        try:
            up.sendall(out)
            up.shutdown(socket.SHUT_WR)
            while True:
                chunk = up.recv(BUF)
                if not chunk:
                    break
                client.sendall(chunk)
        finally:
            up.close()
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(128)
    print("[mid] listening on %s:%d -> %s:%d"
          % (LISTEN_HOST, LISTEN_PORT, UPSTREAM_HOST, UPSTREAM_PORT), flush=True)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
