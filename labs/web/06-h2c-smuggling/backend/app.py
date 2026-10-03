#!/usr/bin/env python3
import os
import socket
import struct
import threading

PORT = int(os.environ.get("PORT", "8000"))
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
BUF = 65536

INDEX_BODY = b"Welcome to the lab\n"
ADMIN_BODY = b"Welcome to the admin panel\nADMIN-SECRET\n"
ADMIN_PREFIX = "/admin"


def recvn(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def send_frame(conn, ftype, flags, stream_id, payload):
    header = (struct.pack(">I", len(payload))[1:] + bytes((ftype, flags))
              + struct.pack(">I", stream_id & 0x7FFFFFFF))
    conn.sendall(header + payload)


def read_frame(conn):
    hdr = recvn(conn, 9)
    length = int.from_bytes(hdr[0:3], "big")
    ftype, flags = hdr[3], hdr[4]
    stream_id = int.from_bytes(hdr[5:9], "big") & 0x7FFFFFFF
    payload = recvn(conn, length) if length else b""
    return ftype, flags, stream_id, payload


def hpack_int(data, pos, prefix):
    mask = (1 << prefix) - 1
    value = data[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    m = 0
    while True:
        b = data[pos]
        pos += 1
        value += (b & 127) << m
        m += 7
        if not (b & 128):
            break
    return value, pos


def parse_header_block(payload):
    fields = {}
    pos, n = 0, len(payload)
    while pos < n:
        b0 = payload[pos]
        if b0 & 0x80:
            break
        if b0 & 0x40:
            prefix = 6
        elif (b0 & 0xF0) == 0x00:
            prefix = 4
        else:
            break
        name_len, pos = hpack_int(payload, pos, prefix)
        name = payload[pos:pos + name_len].decode("latin-1")
        pos += name_len
        if payload[pos] & 0x80:
            break
        value_len, pos = hpack_int(payload, pos, 7)
        value = payload[pos:pos + value_len].decode("latin-1")
        pos += value_len
        fields[name] = value
    return fields


def literal(name, value):
    nb, vb = name.encode("latin-1"), value.encode("latin-1")
    return bytes((len(nb),)) + nb + bytes((len(vb),)) + vb


def serve_h2(conn):
    if recvn(conn, len(PREFACE)) != PREFACE:
        return
    send_frame(conn, 0x4, 0x00, 0, b"")
    while True:
        ftype, flags, stream_id, payload = read_frame(conn)
        if ftype == 0x4 and not (flags & 0x1):
            send_frame(conn, 0x4, 0x1, 0, b"")
        elif ftype == 0x6 and len(payload) == 8:
            send_frame(conn, 0x6, 0x1, 0, payload)
        elif ftype == 0x1:
            fields = parse_header_block(payload)
            path = fields.get(":path", "/").split("?", 1)[0]
            body = ADMIN_BODY if path.startswith(ADMIN_PREFIX) else INDEX_BODY
            send_frame(conn, 0x1, 0x4, stream_id, literal(":status", "200"))
            send_frame(conn, 0x0, 0x1, stream_id, body)
            return


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


def handle(conn):
    try:
        head, _ = recv_head(conn)
        if not head:
            return
        request_line, headers = parse_head(head)
        parts = request_line.split(" ")
        path = parts[1].split("?", 1)[0] if len(parts) >= 2 else "/"
        tokens = [t.strip() for t in headers.get("connection", "").lower().split(",")]
        if "upgrade" in tokens and headers.get("upgrade", "").lower() == "h2c":
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\n"
                         b"Connection: Upgrade\r\nUpgrade: h2c\r\n\r\n")
            serve_h2(conn)
            return
        body = ADMIN_BODY if path.startswith(ADMIN_PREFIX) else INDEX_BODY
        conn.sendall(("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                      "Content-Length: %d\r\nConnection: close\r\n\r\n"
                      % len(body)).encode("latin-1") + body)
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
