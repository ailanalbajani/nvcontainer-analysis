"""Decoder for the DiscAuth loader's HTTP body encryption (stage 1 RVA 0x2CD8).

    python -I transport.py request  <file with the hex POST body>
    python -I transport.py response <file with the raw reply> <k1 hex> <k2 hex>

The two session keys travel inside the request body, so a captured request is
enough to decrypt both directions once TLS has been removed. This tool makes no
network connections.
"""
import struct
import sys

M = (1 << 64) - 1
OUTER_KEY = 0x0C8DEEADE593844E


def rol(v, n):
    n &= 63
    return ((v << n) | (v >> (64 - n))) & M if n else v


def ror(v, n):
    return rol(v, 64 - (n & 63)) if n & 63 else v


def dec(b, k):
    out, acc = bytearray(), 0
    for i, c in enumerate(b):
        kb, x = struct.pack("<Q", k), c
        for j in range(7, -1, -1):
            x = ((x + kb[j]) & 255) ^ kb[(acc + j) & 7]
        m = (((k ^ acc) + 0xFF + i) & M) % 0xFF
        s = m & 7
        x = ((x >> s) | (x << (8 - s))) & 255
        p = (x - m) & 255
        out.append(p)
        acc = rol((acc + p) & M, c)
        k = ror(k, p)
    return bytes(out)


def open_request(hexbody):
    r = dec(bytes.fromhex(hexbody), OUTER_KEY)
    if r[:2] != b"\xfc\xde":
        raise ValueError("request magic mismatch")
    k1, k2 = struct.unpack_from("<QQ", r, 2)
    return k1, k2, dec(dec(r[18:], k2), k1)


def open_response(body, k1, k2):
    return dec(dec(body, k2), k1)


def records(c):
    """Yield (crc32 of field name, value) from a decrypted container."""
    if len(c) < 12 or c[0] != 0xDC:
        raise ValueError("container magic mismatch")
    table, data = struct.unpack_from("<II", c, 4)
    if table % 16 or 12 + table + data > len(c):
        raise ValueError("container sizes out of range")
    for o in range(12, 12 + table, 16):
        flags, key, off, n = struct.unpack_from("<IIII", c, o)
        if flags & 1:
            if off + n > data:
                raise ValueError("record out of range")
            yield key, c[12 + table + off:12 + table + off + n]


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "request":
        with open(sys.argv[2]) as f:
            k1, k2, plain = open_request(f.read().strip())
        print(f"k1={k1:016x} k2={k2:016x}")
    elif len(sys.argv) == 5 and sys.argv[1] == "response":
        with open(sys.argv[2], "rb") as f:
            plain = open_response(f.read(), int(sys.argv[3], 16), int(sys.argv[4], 16))
    else:
        sys.exit(__doc__)
    for key, value in records(plain):
        print(f"{key:08x} {len(value):8d} {value[:32].hex()}")
