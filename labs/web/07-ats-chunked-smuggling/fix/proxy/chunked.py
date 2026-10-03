#!/usr/bin/env python3
"""Parser chunked transfer-coding ala ATS (pra-patch CVE-2025-65114).

Emulasi yang disederhanakan dari ChunkedHandler::read_size() di
proxy/http/HttpTunnel.cc. Flag prev_is_cr hanya diupdate di cabang
tertentu sehingga menjadi basi (stale) antar iterasi -- inilah bug-nya.
"""


class Truncated(Exception):
    """Data belum lengkap; panggil lagi setelah buffer diisi."""


HEXDIGITS = b"0123456789abcdefABCDEF"


def dechunk(data):
    """Urai body chunked. Kembalikan (body, bytes_terkonsumsi).

    Raise ValueError jika framing malformed, Truncated jika data kurang.
    """
    data = bytes(data)
    pos, n = 0, len(data)
    body = bytearray()
    prev_is_cr = False

    while True:
        size, digits = 0, 0
        while pos < n and data[pos:pos + 1] in HEXDIGITS:
            size = (size << 4) + int(data[pos:pos + 1], 16)
            digits += 1
            pos += 1
        if digits == 0:
            if pos >= n:
                raise Truncated()
            raise ValueError("ukuran chunk bukan hex")
        while pos < n and data[pos:pos + 1] in (b" ", b"\t"):
            pos += 1
        if pos >= n:
            raise Truncated()
        if data[pos] == 0x0D:
            prev_is_cr = True
            pos += 1
        if pos >= n:
            raise Truncated()
        if data[pos] != 0x0A:
            raise ValueError("baris ukuran chunk harus diakhiri CRLF")
        pos += 1
        if size == 0:
            if n - pos < 2:
                raise Truncated()
            if data[pos:pos + 2] == b"\r\n":
                return bytes(body), pos + 2
            raise ValueError("trailer chunk harus diakhiri baris kosong")
        if pos + size > n:
            raise Truncated()
        body += data[pos:pos + size]
        pos += size
        if pos >= n:
            raise Truncated()
        if data[pos] == 0x0A:
            if not prev_is_cr:
                raise ValueError("LF tanpa CR setelah data chunk")
            pos += 1
            continue
        if data[pos] == 0x0D:
            prev_is_cr = True
            pos += 1
            if pos >= n:
                raise Truncated()
            if data[pos] == 0x0A:
                pos += 1
                continue
        raise ValueError("data chunk harus diakhiri CRLF")
