#!/usr/bin/env python3
"""Gateway HTTP/2 (h2c, prior knowledge) -> HTTP/1.1 untuk Lab 9.

Menerima koneksi HTTP/2 cleartext, menerjemahkan setiap stream menjadi
satu request HTTP/1.1, dan meneruskannya ke backend melalui satu
koneksi keep-alive bersama.
"""
import os
import socket
import struct
import threading

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "80"))
BACKEND_HOST = os.environ.get("BACKEND_HOST", "backend")
BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "8000"))

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

F_DATA = 0x0
F_HEADERS = 0x1
F_RST = 0x3
F_SETTINGS = 0x4
F_PING = 0x6
F_GOAWAY = 0x7
F_WINDOW_UPDATE = 0x8
F_CONTINUATION = 0x9

FL_ACK = 0x1
FL_END_STREAM = 0x1
FL_END_HEADERS = 0x4
FL_PADDED = 0x8

SETTINGS_HEADER_TABLE_SIZE = 0x1

REASONS = {200: "OK", 400: "Bad Request", 502: "Bad Gateway"}

_STATIC = [
    (b":authority", b""), (b":method", b"GET"), (b":method", b"POST"),
    (b":path", b"/"), (b":path", b"/index.html"), (b":scheme", b"http"),
    (b":scheme", b"https"), (b":status", b"200"), (b":status", b"204"),
    (b":status", b"206"), (b":status", b"304"), (b":status", b"400"),
    (b":status", b"404"), (b":status", b"500"), (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"), (b"accept-language", b""),
    (b"accept-ranges", b""), (b"accept", b""),
    (b"access-control-allow-origin", b""), (b"age", b""), (b"allow", b""),
    (b"authorization", b""), (b"cache-control", b""),
    (b"content-disposition", b""), (b"content-encoding", b""),
    (b"content-language", b""), (b"content-length", b""),
    (b"content-location", b""), (b"content-range", b""),
    (b"content-type", b""), (b"cookie", b""), (b"date", b""),
    (b"etag", b""), (b"expect", b""), (b"expires", b""),
    (b"from", b""), (b"host", b""), (b"if-match", b""),
    (b"if-modified-since", b""), (b"if-none-match", b""),
    (b"if-range", b""), (b"if-unmodified-since", b""),
    (b"last-modified", b""), (b"link", b""), (b"location", b""),
    (b"max-forwards", b""), (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""), (b"range", b""), (b"referer", b""),
    (b"refresh", b""), (b"retry-after", b""), (b"server", b""),
    (b"set-cookie", b""), (b"strict-transport-security", b""),
    (b"transfer-encoding", b""), (b"user-agent", b""), (b"vary", b""),
    (b"via", b""), (b"www-authenticate", b""),
]

_HUFFMAN = [
    (0x1ff8, 13),  # 0 
    (0x7fffd8, 23),  # 1 
    (0xfffffe2, 28),  # 2 
    (0xfffffe3, 28),  # 3 
    (0xfffffe4, 28),  # 4 
    (0xfffffe5, 28),  # 5 
    (0xfffffe6, 28),  # 6 
    (0xfffffe7, 28),  # 7 
    (0xfffffe8, 28),  # 8 
    (0xffffea, 24),  # 9 
    (0x3ffffffc, 30),  # 10 
    (0xfffffe9, 28),  # 11 
    (0xfffffea, 28),  # 12 
    (0x3ffffffd, 30),  # 13 
    (0xfffffeb, 28),  # 14 
    (0xfffffec, 28),  # 15 
    (0xfffffed, 28),  # 16 
    (0xfffffee, 28),  # 17 
    (0xfffffef, 28),  # 18 
    (0xffffff0, 28),  # 19 
    (0xffffff1, 28),  # 20 
    (0xffffff2, 28),  # 21 
    (0x3ffffffe, 30),  # 22 
    (0xffffff3, 28),  # 23 
    (0xffffff4, 28),  # 24 
    (0xffffff5, 28),  # 25 
    (0xffffff6, 28),  # 26 
    (0xffffff7, 28),  # 27 
    (0xffffff8, 28),  # 28 
    (0xffffff9, 28),  # 29 
    (0xffffffa, 28),  # 30 
    (0xffffffb, 28),  # 31 
    (0x14, 6),  # 32  
    (0x3f8, 10),  # 33 !
    (0x3f9, 10),  # 34 "
    (0xffa, 12),  # 35 #
    (0x1ff9, 13),  # 36 $
    (0x15, 6),  # 37 %
    (0xf8, 8),  # 38 &
    (0x7fa, 11),  # 39 '
    (0x3fa, 10),  # 40 (
    (0x3fb, 10),  # 41 )
    (0xf9, 8),  # 42 *
    (0x7fb, 11),  # 43 +
    (0xfa, 8),  # 44 ,
    (0x16, 6),  # 45 -
    (0x17, 6),  # 46 .
    (0x18, 6),  # 47 /
    (0x0, 5),  # 48 0
    (0x1, 5),  # 49 1
    (0x2, 5),  # 50 2
    (0x19, 6),  # 51 3
    (0x1a, 6),  # 52 4
    (0x1b, 6),  # 53 5
    (0x1c, 6),  # 54 6
    (0x1d, 6),  # 55 7
    (0x1e, 6),  # 56 8
    (0x1f, 6),  # 57 9
    (0x5c, 7),  # 58 :
    (0xfb, 8),  # 59 ;
    (0x7ffc, 15),  # 60 <
    (0x20, 6),  # 61 =
    (0xffb, 12),  # 62 >
    (0x3fc, 10),  # 63 ?
    (0x1ffa, 13),  # 64 @
    (0x21, 6),  # 65 A
    (0x5d, 7),  # 66 B
    (0x5e, 7),  # 67 C
    (0x5f, 7),  # 68 D
    (0x60, 7),  # 69 E
    (0x61, 7),  # 70 F
    (0x62, 7),  # 71 G
    (0x63, 7),  # 72 H
    (0x64, 7),  # 73 I
    (0x65, 7),  # 74 J
    (0x66, 7),  # 75 K
    (0x67, 7),  # 76 L
    (0x68, 7),  # 77 M
    (0x69, 7),  # 78 N
    (0x6a, 7),  # 79 O
    (0x6b, 7),  # 80 P
    (0x6c, 7),  # 81 Q
    (0x6d, 7),  # 82 R
    (0x6e, 7),  # 83 S
    (0x6f, 7),  # 84 T
    (0x70, 7),  # 85 U
    (0x71, 7),  # 86 V
    (0x72, 7),  # 87 W
    (0xfc, 8),  # 88 X
    (0x73, 7),  # 89 Y
    (0xfd, 8),  # 90 Z
    (0x1ffb, 13),  # 91 [
    (0x7fff0, 19),  # 92 \
    (0x1ffc, 13),  # 93 ]
    (0x3ffc, 14),  # 94 ^
    (0x22, 6),  # 95 _
    (0x7ffd, 15),  # 96 `
    (0x3, 5),  # 97 a
    (0x23, 6),  # 98 b
    (0x4, 5),  # 99 c
    (0x24, 6),  # 100 d
    (0x5, 5),  # 101 e
    (0x25, 6),  # 102 f
    (0x26, 6),  # 103 g
    (0x27, 6),  # 104 h
    (0x6, 5),  # 105 i
    (0x74, 7),  # 106 j
    (0x75, 7),  # 107 k
    (0x28, 6),  # 108 l
    (0x29, 6),  # 109 m
    (0x2a, 6),  # 110 n
    (0x7, 5),  # 111 o
    (0x2b, 6),  # 112 p
    (0x76, 7),  # 113 q
    (0x2c, 6),  # 114 r
    (0x8, 5),  # 115 s
    (0x9, 5),  # 116 t
    (0x2d, 6),  # 117 u
    (0x77, 7),  # 118 v
    (0x78, 7),  # 119 w
    (0x79, 7),  # 120 x
    (0x7a, 7),  # 121 y
    (0x7b, 7),  # 122 z
    (0x7ffe, 15),  # 123 {
    (0x7fc, 11),  # 124 |
    (0x3ffd, 14),  # 125 }
    (0x1ffd, 13),  # 126 ~
    (0xffffffc, 28),  # 127 
    (0xfffe6, 20),  # 128 
    (0x3fffd2, 22),  # 129 
    (0xfffe7, 20),  # 130 
    (0xfffe8, 20),  # 131 
    (0x3fffd3, 22),  # 132 
    (0x3fffd4, 22),  # 133 
    (0x3fffd5, 22),  # 134 
    (0x7fffd9, 23),  # 135 
    (0x3fffd6, 22),  # 136 
    (0x7fffda, 23),  # 137 
    (0x7fffdb, 23),  # 138 
    (0x7fffdc, 23),  # 139 
    (0x7fffdd, 23),  # 140 
    (0x7fffde, 23),  # 141 
    (0xffffeb, 24),  # 142 
    (0x7fffdf, 23),  # 143 
    (0xffffec, 24),  # 144 
    (0xffffed, 24),  # 145 
    (0x3fffd7, 22),  # 146 
    (0x7fffe0, 23),  # 147 
    (0xffffee, 24),  # 148 
    (0x7fffe1, 23),  # 149 
    (0x7fffe2, 23),  # 150 
    (0x7fffe3, 23),  # 151 
    (0x7fffe4, 23),  # 152 
    (0x1fffdc, 21),  # 153 
    (0x3fffd8, 22),  # 154 
    (0x7fffe5, 23),  # 155 
    (0x3fffd9, 22),  # 156 
    (0x7fffe6, 23),  # 157 
    (0x7fffe7, 23),  # 158 
    (0xffffef, 24),  # 159 
    (0x3fffda, 22),  # 160 
    (0x1fffdd, 21),  # 161 
    (0xfffe9, 20),  # 162 
    (0x3fffdb, 22),  # 163 
    (0x3fffdc, 22),  # 164 
    (0x7fffe8, 23),  # 165 
    (0x7fffe9, 23),  # 166 
    (0x1fffde, 21),  # 167 
    (0x7fffea, 23),  # 168 
    (0x3fffdd, 22),  # 169 
    (0x3fffde, 22),  # 170 
    (0xfffff0, 24),  # 171 
    (0x1fffdf, 21),  # 172 
    (0x3fffdf, 22),  # 173 
    (0x7fffeb, 23),  # 174 
    (0x7fffec, 23),  # 175 
    (0x1fffe0, 21),  # 176 
    (0x1fffe1, 21),  # 177 
    (0x3fffe0, 22),  # 178 
    (0x1fffe2, 21),  # 179 
    (0x7fffed, 23),  # 180 
    (0x3fffe1, 22),  # 181 
    (0x7fffee, 23),  # 182 
    (0x7fffef, 23),  # 183 
    (0xfffea, 20),  # 184 
    (0x3fffe2, 22),  # 185 
    (0x3fffe3, 22),  # 186 
    (0x3fffe4, 22),  # 187 
    (0x7ffff0, 23),  # 188 
    (0x3fffe5, 22),  # 189 
    (0x3fffe6, 22),  # 190 
    (0x7ffff1, 23),  # 191 
    (0x3ffffe0, 26),  # 192 
    (0x3ffffe1, 26),  # 193 
    (0xfffeb, 20),  # 194 
    (0x7fff1, 19),  # 195 
    (0x3fffe7, 22),  # 196 
    (0x7ffff2, 23),  # 197 
    (0x3fffe8, 22),  # 198 
    (0x1ffffec, 25),  # 199 
    (0x3ffffe2, 26),  # 200 
    (0x3ffffe3, 26),  # 201 
    (0x3ffffe4, 26),  # 202 
    (0x7ffffde, 27),  # 203 
    (0x7ffffdf, 27),  # 204 
    (0x3ffffe5, 26),  # 205 
    (0xfffff1, 24),  # 206 
    (0x1ffffed, 25),  # 207 
    (0x7fff2, 19),  # 208 
    (0x1fffe3, 21),  # 209 
    (0x3ffffe6, 26),  # 210 
    (0x7ffffe0, 27),  # 211 
    (0x7ffffe1, 27),  # 212 
    (0x3ffffe7, 26),  # 213 
    (0x7ffffe2, 27),  # 214 
    (0xfffff2, 24),  # 215 
    (0x1fffe4, 21),  # 216 
    (0x1fffe5, 21),  # 217 
    (0x3ffffe8, 26),  # 218 
    (0x3ffffe9, 26),  # 219 
    (0xffffffd, 28),  # 220 
    (0x7ffffe3, 27),  # 221 
    (0x7ffffe4, 27),  # 222 
    (0x7ffffe5, 27),  # 223 
    (0xfffec, 20),  # 224 
    (0xfffff3, 24),  # 225 
    (0xfffed, 20),  # 226 
    (0x1fffe6, 21),  # 227 
    (0x3fffe9, 22),  # 228 
    (0x1fffe7, 21),  # 229 
    (0x1fffe8, 21),  # 230 
    (0x7ffff3, 23),  # 231 
    (0x3fffea, 22),  # 232 
    (0x3fffeb, 22),  # 233 
    (0x1ffffee, 25),  # 234 
    (0x1ffffef, 25),  # 235 
    (0xfffff4, 24),  # 236 
    (0xfffff5, 24),  # 237 
    (0x3ffffea, 26),  # 238 
    (0x7ffff4, 23),  # 239 
    (0x3ffffeb, 26),  # 240 
    (0x7ffffe6, 27),  # 241 
    (0x3ffffec, 26),  # 242 
    (0x3ffffed, 26),  # 243 
    (0x7ffffe7, 27),  # 244 
    (0x7ffffe8, 27),  # 245 
    (0x7ffffe9, 27),  # 246 
    (0x7ffffea, 27),  # 247 
    (0x7ffffeb, 27),  # 248 
    (0xffffffe, 28),  # 249 
    (0x7ffffec, 27),  # 250 
    (0x7ffffed, 27),  # 251 
    (0x7ffffee, 27),  # 252 
    (0x7ffffef, 27),  # 253 
    (0x7fffff0, 27),  # 254 
    (0x3ffffee, 26),  # 255 
]

_HUFFMAN_TRIE = None


def _build_huffman_trie():
    root = {}
    for sym in range(256):
        code, bits = _HUFFMAN[sym]
        node = root
        for i in range(bits - 1, -1, -1):
            node = node.setdefault((code >> i) & 1, {})
        node["s"] = sym
    return root


def _huffman_decode(raw):
    out = bytearray()
    node = _HUFFMAN_TRIE
    total = len(raw) * 8
    pos = 0
    while pos < total:
        bit = (raw[pos // 8] >> (7 - (pos % 8))) & 1
        nxt = node.get(bit)
        if nxt is None:
            rest = total - pos
            tail = int.from_bytes(raw[pos // 8:], "big") & ((1 << rest) - 1)
            if tail == (1 << rest) - 1:
                break
            raise ValueError("huffman rusak")
        node = nxt
        pos += 1
        if "s" in node:
            out.append(node["s"])
            node = _HUFFMAN_TRIE
    return bytes(out)


def _decode_int(data, pos, prefix_bits):
    mask = (1 << prefix_bits) - 1
    val = data[pos] & mask
    pos += 1
    if val < mask:
        return val, pos
    m = 0
    while True:
        b = data[pos]
        pos += 1
        val += (b & 127) << m
        m += 7
        if not (b & 128):
            break
    return val, pos


def _decode_string(data, pos):
    huffman = bool(data[pos] & 0x80)
    length, pos = _decode_int(data, pos, 7)
    raw = data[pos:pos + length]
    pos += length
    if huffman:
        return _huffman_decode(raw), pos
    return raw, pos


class _HpackDecoder:
    def __init__(self):
        self.dyn = []
        self.max_size = 4096
        self.size = 0

    def _get(self, index):
        if 1 <= index <= 61:
            return _STATIC[index - 1]
        i = index - 62
        if 0 <= i < len(self.dyn):
            return self.dyn[i]
        raise ValueError("indeks HPACK di luar rentang")

    def _evict(self):
        while self.size > self.max_size and self.dyn:
            n, v = self.dyn.pop()
            self.size -= len(n) + len(v) + 32

    def _add(self, name, value):
        self.dyn.insert(0, (name, value))
        self.size += len(name) + len(value) + 32
        self._evict()

    def decode(self, data):
        headers = []
        pos = 0
        n = len(data)
        while pos < n:
            b = data[pos]
            if b & 0x80:
                idx, pos = _decode_int(data, pos, 7)
                headers.append(self._get(idx))
            elif b & 0x40:
                idx, pos = _decode_int(data, pos, 6)
                if idx == 0:
                    name, pos = _decode_string(data, pos)
                else:
                    name = self._get(idx)[0]
                value, pos = _decode_string(data, pos)
                self._add(name, value)
                headers.append((name, value))
            elif b & 0x20:
                new_max, pos = _decode_int(data, pos, 5)
                self.max_size = new_max
                self._evict()
            else:
                idx, pos = _decode_int(data, pos, 4)
                if idx == 0:
                    name, pos = _decode_string(data, pos)
                else:
                    name = self._get(idx)[0]
                value, pos = _decode_string(data, pos)
                headers.append((name, value))
        return headers


def _read_exact(rf, n):
    data = b""
    while len(data) < n:
        chunk = rf.read(n - len(data))
        if not chunk:
            raise ConnectionError("EOF")
        data += chunk
    return data


def _read_frame(rf):
    raw = _read_exact(rf, 9)
    length = int.from_bytes(raw[0:3], "big")
    ftype = raw[3]
    flags = raw[4]
    sid = int.from_bytes(raw[5:9], "big") & 0x7FFFFFFF
    payload = _read_exact(rf, length) if length else b""
    return ftype, flags, sid, payload


def _send_frame(sock, ftype, flags, sid, payload):
    header = (len(payload).to_bytes(3, "big") + bytes([ftype, flags])
              + (sid & 0x7FFFFFFF).to_bytes(4, "big"))
    sock.sendall(header + payload)


def _encode_int(value, prefix_bits):
    mask = (1 << prefix_bits) - 1
    if value < mask:
        return bytes([value])
    out = bytearray([mask])
    value -= mask
    while value >= 128:
        out.append((value % 128) + 128)
        value //= 128
    out.append(value)
    return bytes(out)


def _hpack_literal(name, value):
    out = bytearray(b"\x00")
    out += _encode_int(len(name), 7)
    out += name
    out += _encode_int(len(value), 7)
    out += value
    return bytes(out)


def _respond(sock, sid, status, body):
    hp = b""
    if status == 200:
        hp += b"\x88"
    else:
        hp += _hpack_literal(b":status", str(status).encode("latin-1"))
    hp += _hpack_literal(b"content-length", str(len(body)).encode("latin-1"))
    hp += _hpack_literal(b"content-type", b"text/plain")
    _send_frame(sock, F_HEADERS, FL_END_HEADERS, sid, hp)
    _send_frame(sock, F_DATA, FL_END_STREAM, sid, body)


_be_lock = threading.Lock()
_be_sock = None
_be_rf = None


def _backend_close():
    global _be_sock, _be_rf
    try:
        if _be_sock is not None:
            _be_sock.close()
    except OSError:
        pass
    _be_sock = None
    _be_rf = None


def _read_h1_response(rf):
    line = rf.readline(65536)
    if not line:
        raise ConnectionError("backend menutup koneksi")
    parts = line.decode("latin-1").rstrip("\r\n").split(" ", 2)
    status = int(parts[1])
    headers = {}
    while True:
        h = rf.readline(65536)
        if not h:
            raise ConnectionError("backend menutup koneksi")
        h = h.decode("latin-1").rstrip("\r\n")
        if h == "":
            break
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    try:
        n = int(headers.get("content-length", "0") or "0")
    except ValueError:
        n = 0
    body = b""
    while len(body) < n:
        chunk = rf.read(n - len(body))
        if not chunk:
            raise ConnectionError("backend menutup koneksi")
        body += chunk
    return status, headers, body


def _backend_exchange(raw):
    global _be_sock, _be_rf
    with _be_lock:
        for _ in range(2):
            try:
                if _be_sock is None:
                    _be_sock = socket.create_connection(
                        (BACKEND_HOST, BACKEND_PORT), timeout=10)
                    _be_rf = _be_sock.makefile("rb")
                _be_sock.sendall(raw)
                return _read_h1_response(_be_rf)
            except (OSError, ConnectionError, ValueError):
                _backend_close()
        raise OSError("backend tidak terjangkau")


def _strip_padding(payload, flags):
    if flags & FL_PADDED:
        pad = payload[0]
        return payload[1:len(payload) - pad] if pad else payload[1:]
    return payload


def _read_header_block(rf, payload, flags):
    frags = [_strip_padding(payload, flags)]
    end_stream = bool(flags & FL_END_STREAM)
    while not (flags & FL_END_HEADERS):
        ftype, flags, _sid, payload = _read_frame(rf)
        if ftype != F_CONTINUATION:
            raise ValueError("mengharap CONTINUATION")
        frags.append(payload)
        end_stream = end_stream or bool(flags & FL_END_STREAM)
    return b"".join(frags), end_stream


def _process(conn, sid, st):
    headers = st["headers"]
    body = bytes(st["body"])
    pseudo = {}
    others = []
    for name, value in headers:
        if name.startswith(b":"):
            pseudo[name] = value
        else:
            others.append((name, value))
    try:
        method = pseudo[b":method"].decode("latin-1")
        path = pseudo[b":path"].decode("latin-1")
        authority = pseudo.get(b":authority", b"").decode("latin-1")
    except KeyError:
        _respond(conn, sid, 400, b"pseudo-header tidak lengkap")
        return
    lines = ["%s %s HTTP/1.1" % (method, path)]
    if authority:
        lines.append("Host: %s" % authority)
    for name, value in others:
        lines.append("%s: %s" % (name.decode("latin-1"),
                                 value.decode("latin-1")))
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body
    try:
        status, _rh, resp_body = _backend_exchange(raw)
    except OSError:
        _respond(conn, sid, 502, b"backend tidak terjangkau")
        return
    _respond(conn, sid, status, resp_body)


def _handle_client(conn):
    conn.settimeout(30)
    try:
        rf = conn.makefile("rb")
        if _read_exact(rf, 24) != PREFACE:
            return
        dec = _HpackDecoder()
        _send_frame(conn, F_SETTINGS, 0, 0, b"")
        try:
            ftype, flags, _sid, payload = _read_frame(rf)
        except (ConnectionError, ValueError):
            return
        if ftype == F_SETTINGS and not (flags & FL_ACK):
            pos = 0
            while pos + 6 <= len(payload):
                ident = int.from_bytes(payload[pos:pos + 2], "big")
                val = int.from_bytes(payload[pos + 2:pos + 6], "big")
                if ident == SETTINGS_HEADER_TABLE_SIZE:
                    dec.max_size = val
                    dec._evict()
                pos += 6
            _send_frame(conn, F_SETTINGS, FL_ACK, 0, b"")
        streams = {}
        while True:
            try:
                ftype, flags, sid, payload = _read_frame(rf)
            except (ConnectionError, ValueError):
                break
            if ftype == F_DATA:
                st = streams.get(sid)
                if st is None or st["done"]:
                    continue
                data = _strip_padding(payload, flags)
                st["body"] += data
                if data:
                    win = len(data).to_bytes(4, "big")
                    _send_frame(conn, F_WINDOW_UPDATE, 0, sid, win)
                    _send_frame(conn, F_WINDOW_UPDATE, 0, 0, win)
                if flags & FL_END_STREAM:
                    st["done"] = True
                    try:
                        _process(conn, sid, st)
                    except (OSError, ConnectionError, ValueError):
                        break
            elif ftype == F_HEADERS:
                try:
                    block, end_stream = _read_header_block(rf, payload, flags)
                    headers = dec.decode(block)
                except ValueError:
                    _send_frame(conn, F_RST, 0, sid,
                                (0x1).to_bytes(4, "big"))
                    continue
                st = streams.get(sid)
                if st is None:
                    st = {"headers": [], "body": bytearray(), "done": False}
                    streams[sid] = st
                st["headers"] = headers
                if end_stream:
                    st["done"] = True
                    try:
                        _process(conn, sid, st)
                    except (OSError, ConnectionError, ValueError):
                        break
            elif ftype == F_SETTINGS:
                if not (flags & FL_ACK):
                    _send_frame(conn, F_SETTINGS, FL_ACK, 0, b"")
            elif ftype == F_PING:
                if not (flags & FL_ACK):
                    _send_frame(conn, F_PING, FL_ACK, 0, payload)
            elif ftype == F_GOAWAY:
                break
    except (OSError, ConnectionError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    global _HUFFMAN_TRIE
    _HUFFMAN_TRIE = _build_huffman_trie()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=_handle_client, args=(conn,),
                         daemon=True).start()


if __name__ == "__main__":
    main()
