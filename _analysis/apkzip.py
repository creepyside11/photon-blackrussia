#!/usr/bin/env python3
"""Faithful APK repack: copy every entry's raw bytes, preserve all ZIP headers.

Only the entries passed in `replace` are recompressed. Everything else keeps
its original compressed payload, CRC, flags, versions, attributes and extras,
so the result differs from the source only where it must.
"""
import struct
import zlib

LOCAL_SIG = 0x04034B50
CD_SIG = 0x02014B50
EOCD_SIG = 0x06054B50
DD_SIG = 0x08074B50
ALIGN_ID = 0xD935


class Entry:
    __slots__ = ("name", "raw_name", "ver", "flags", "method", "mtime", "mdate",
                 "crc", "csize", "usize", "extra", "cmade", "cneed", "iattr",
                 "eattr", "off", "data", "descriptor")


def read_entries(raw):
    eocd = raw.rfind(struct.pack("<I", EOCD_SIG))
    if eocd < 0:
        raise ValueError("no EOCD")
    cd_size, cd_off = struct.unpack_from("<II", raw, eocd + 12)
    entries = []
    p = cd_off
    while p < cd_off + cd_size and struct.unpack_from("<I", raw, p)[0] == CD_SIG:
        (_, cmade, cneed, flags, method, mtime, mdate, crc, csize, usize,
         nlen, elen, clen, disk, iattr, eattr, off) = struct.unpack_from(
            "<IHHHHHHIIIHHHHHII", raw, p)
        e = Entry()
        e.raw_name = raw[p + 46:p + 46 + nlen]
        e.name = e.raw_name.decode("utf-8", "surrogateescape")
        e.cmade, e.cneed, e.flags, e.method = cmade, cneed, flags, method
        e.mtime, e.mdate, e.crc, e.csize, e.usize = mtime, mdate, crc, csize, usize
        e.iattr, e.eattr, e.off = iattr, eattr, off
        e.extra = raw[p + 46 + nlen:p + 46 + nlen + elen]
        entries.append(e)
        p += 46 + nlen + elen + clen
    if p != cd_off + cd_size:
        raise ValueError("central directory size mismatch")

    entries.sort(key=lambda x: x.off)
    for idx, e in enumerate(entries):
        lh = struct.unpack_from("<IHHHHHIIIHH", raw, e.off)
        if lh[0] != LOCAL_SIG:
            raise ValueError("bad local header for " + e.name)
        e.ver, e.flags, e.method = lh[1], lh[2], lh[3]
        e.mtime, e.mdate = lh[4], lh[5]
        nlen, elen = lh[9], lh[10]
        e.extra = raw[e.off + 30 + nlen:e.off + 30 + nlen + elen]
        e.data = raw[e.off + 30 + nlen + elen:e.off + 30 + nlen + elen + e.csize]
        end = e.off + 30 + nlen + elen + e.csize
        nxt = entries[idx + 1].off if idx + 1 < len(entries) else cd_off
        gap = nxt - end
        e.descriptor = None
        if e.flags & 0x08:
            if gap == 16 and struct.unpack_from("<I", raw, end)[0] == DD_SIG:
                e.descriptor = raw[end:end + 16]
            elif gap == 12:
                e.descriptor = raw[end:end + 12]
    return entries


def _strip_align(extra):
    """Drop a trailing zipalign extra field so padding can be recomputed."""
    out = b""
    p = 0
    while p + 4 <= len(extra):
        hid, hlen = struct.unpack_from("<HH", extra, p)
        if p + 4 + hlen > len(extra):
            break
        if hid != ALIGN_ID:
            out += extra[p:p + 4 + hlen]
        p += 4 + hlen
    return out


def _align_extra(base, offset, name_len, align=4):
    header = 30 + name_len
    need = (align - ((offset + header + len(base)) % align)) % align
    pad = need if need >= 4 else need + 4
    extra = base + struct.pack("<HH", ALIGN_ID, pad - 4) + b"\x00" * (pad - 4)
    if (offset + header + len(extra)) % align:
        raise ValueError("alignment failed")
    return extra


def rebuild(raw, replace=None, deflate_level=9):
    replace = replace or {}
    entries = read_entries(raw)
    out = bytearray()
    cd = bytearray()

    for e in entries:
        name = e.raw_name
        if e.name in replace:
            data = replace[e.name]
            crc = zlib.crc32(data) & 0xFFFFFFFF
            if e.method == 8:
                co = zlib.compressobj(deflate_level, zlib.DEFLATED, -15)
                payload = co.compress(data) + co.flush()
            else:
                payload = data
            usize, csize = len(data), len(payload)
        else:
            payload = e.data
            crc, csize, usize = e.crc, e.csize, e.usize

        extra = _strip_align(e.extra)
        if e.method == 0:
            extra = _align_extra(extra, len(out), len(name))

        local_flags = e.flags
        if e.descriptor is None:
            local_flags &= ~0x08

        out += struct.pack("<IHHHHHIIIHH", LOCAL_SIG, e.ver, local_flags, e.method,
                           e.mtime, e.mdate, crc, csize, usize,
                           len(name), len(extra))
        out += name
        out += extra
        data_off = len(out)
        out += payload

        if e.descriptor is not None:
            if len(e.descriptor) == 16:
                out += struct.pack("<IIII", DD_SIG, crc, csize, usize)
            else:
                out += struct.pack("<III", crc, csize, usize)

        cd += struct.pack("<IHHHHHHIIIHHHHHII", CD_SIG, e.cmade, e.cneed,
                          local_flags, e.method, e.mtime, e.mdate, crc, csize,
                          usize, len(name), 0, 0, 0, e.iattr, e.eattr, data_off)
        cd += name

    cd_off = len(out)
    out += cd
    out += struct.pack("<IHHHHIIH", EOCD_SIG, 0, 0, len(entries), len(entries),
                       len(cd), cd_off, 0)
    return bytes(out)
