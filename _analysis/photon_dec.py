#!/usr/bin/env python3
"""Расшифровка строк libPhoton.so.

Строки упакованы 16-байтовыми кусками без нуль-терминаторов и зашифрованы
XOR'ом с 8-байтным ключом, который лежит прямо в .rodata.

    python3 photon_dec.py                 # все строки
    python3 photon_dec.py --urls          # только URL
    python3 photon_dec.py --grep крест    # поиск по подстроке
    python3 photon_dec.py --chunk 16      # по 16-байтовым кускам
"""
import re
import sys

SO = "libPhoton.so"
KEY_OFF = 0x1b1560          # 8 байт, дальше повтор
RODATA = (0x1ad000, 0x35a62b)


def load_key(path=SO):
    with open(path, "rb") as f:
        f.seek(KEY_OFF)
        return f.read(8)


def decrypt(path=SO):
    with open(path, "rb") as f:
        f.seek(RODATA[0])
        buf = bytearray(f.read(RODATA[1] - RODATA[0]))
    key = load_key(path)
    for i in range(len(buf)):
        buf[i] ^= key[i % len(key)]
    return bytes(buf)


def runs(blob, lo=RODATA[0], minlen=4):
    """ASCII-островки с виртуальными адресами."""
    for m in re.finditer(rb"[ -~]{%d,300}" % minlen, blob):
        yield lo + m.start(), m.group().decode("latin-1")


def chunks(blob, size=16, lo=RODATA[0]):
    for off in range(0, len(blob) - size + 1, size):
        yield lo + off, blob[off:off + size].decode("latin-1")


def main():
    blob = decrypt()
    argv = sys.argv[1:]

    if "--urls" in argv:
        pat = re.compile(r"https?://[^\s\x00-\x1f\"'<>]{3,120}")
        seen = set()
        for off, s in runs(blob, minlen=3):
            for m in pat.finditer(s):
                u = m.group()
                if u not in seen:
                    seen.add(u)
                    print(f"{off:#08x}  {u}")
        return

    if "--chunk" in argv:
        size = int(argv[argv.index("--chunk") + 1]) if len(argv) > argv.index("--chunk") + 1 else 16
        for off, s in chunks(blob, size):
            print(f"{off:#08x}  {s}")
        return

    if "--grep" in argv:
        needle = argv[argv.index("--grep") + 1].lower()
        for off, s in runs(blob):
            if needle in s.lower():
                print(f"{off:#08x}  {s}")
        return

    for off, s in runs(blob):
        print(f"{off:#08x}  {s}")


if __name__ == "__main__":
    main()
