#!/usr/bin/env python3
"""Repack + APK Signature Scheme v2 signing, no Java required.

The content digest must cover the EOCD whose central-directory offset points
to the CD position *after* the signing block is inserted.  That offset depends
on the block length, and the block length depends on the signature length.
For RSA-2048 every length is stable, so we sign twice: once with a placeholder
digest to measure, once with the real digest.
"""
import hashlib
import io
import struct
import zipfile

MAGIC = b"APK Sig Block 42"
V2_ID = 0x7109871A
SHA256_RSA = 0x0103
ATTR_STRIPPING_PROTECTION = 0xBEEFF00D
CHUNK = 1048576


def lp(data):
    return struct.pack("<I", len(data)) + data


def split_zip(raw):
    """Return (contents, central_directory, eocd_without_cd_fixup)."""
    i = raw.rfind(b"PK\x05\x06")
    if i < 0:
        raise ValueError("EOCD not found")
    eocd = raw[i:]
    cd_off = struct.unpack_from("<I", eocd, 16)[0]
    if cd_off > i:
        raise ValueError("bad central directory offset")
    return raw[:cd_off], raw[cd_off:i], eocd


def content_digest(sections):
    """Android v2 chunked digest: 1 MiB chunks, 0xa5 framing, 0x5a top level."""
    chunk_digests = []
    for section in sections:
        for i in range(0, len(section), CHUNK):
            chunk = section[i:i + CHUNK]
            h = hashlib.sha256()
            h.update(b"\xa5")
            h.update(struct.pack("<I", len(chunk)))
            h.update(chunk)
            chunk_digests.append(h.digest())
    top = hashlib.sha256()
    top.update(b"\x5a")
    top.update(struct.pack("<I", len(chunk_digests)))
    for d in chunk_digests:
        top.update(d)
    return top.digest()


def _signer_value(digest, key, cert_der):
    pub = key.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization",
                   fromlist=["Encoding"]).Encoding.DER,
        __import__("cryptography.hazmat.primitives.serialization",
                   fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo,
    )

    digest_record = struct.pack("<I", SHA256_RSA) + lp(digest)
    digests = lp(lp(digest_record))          # lp(sequence of lp(record))
    certs = lp(lp(cert_der))                 # lp(sequence of lp(cert))
    attrs = lp(lp(struct.pack("<II", ATTR_STRIPPING_PROTECTION, 3)))
    signed_data = digests + certs + attrs

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    signature = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())

    sig_record = struct.pack("<I", SHA256_RSA) + lp(signature)
    signatures = lp(lp(sig_record))
    signer = lp(signed_data) + signatures + lp(pub)
    return lp(lp(signer))


def _block_length(pairs):
    return 8 + sum(8 + 4 + len(value) for _, value in pairs) + 8 + len(MAGIC)


def _build_block(pairs):
    body = b""
    for pair_id, value in pairs:
        body += struct.pack("<Q", len(value) + 4)
        body += struct.pack("<I", pair_id)
        body += value
    size = len(body) + 8 + len(MAGIC)
    return struct.pack("<Q", size) + body + struct.pack("<Q", size) + MAGIC


def sign_v2(raw, key, cert_der):
    contents, cd, eocd_raw = split_zip(raw)

    # Digest covers the unsigned layout: the CD would sit directly after the
    # entry data, so the hashed EOCD carries cd_offset == len(contents).
    eocd_hashed = bytearray(eocd_raw)
    struct.pack_into("<I", eocd_hashed, 16, len(contents))
    digest = content_digest((contents, cd, bytes(eocd_hashed)))

    value = _signer_value(digest, key, cert_der)
    block = _build_block([(V2_ID, value)])

    # The EOCD written to disk points past the signing block.
    eocd_final = bytearray(eocd_raw)
    struct.pack_into("<I", eocd_final, 16, len(contents) + len(block))
    return contents + block + cd + bytes(eocd_final)


def _alignment_extra(current_offset, name_len, base_extra, align=4):
    """Extra field that lands the file data at a multiple of `align`."""
    header = 30 + name_len
    need = (align - ((current_offset + header + len(base_extra)) % align)) % align
    pad = need if need >= 4 else need + 4
    extra = base_extra + struct.pack("<HH", 0xD935, pad - 4) + b"\x00" * (pad - 4)
    if (current_offset + header + len(extra)) % align:
        raise ValueError("alignment failed")
    return extra


def repack(src, dst, replace=None):
    """Rewrite the ZIP, preserving entry order, method and metadata."""
    replace = replace or {}
    zin = zipfile.ZipFile(src, "r")
    count = 0
    with open(dst, "wb") as fh:
        with zipfile.ZipFile(fh, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zout:
            for info in zin.infolist():
                data = replace.get(info.filename)
                if data is None:
                    data = zin.read(info.filename)
                zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                zi.internal_attr = info.internal_attr
                zi.create_system = info.create_system
                # Match the original: every entry carries the UTF-8 flag.
                zi.flag_bits = info.flag_bits | 0x800
                base_extra = info.extra or b""
                if info.compress_type == zipfile.ZIP_STORED:
                    name_len = len(info.filename.encode("utf-8"))
                    zi.extra = _alignment_extra(fh.tell(), name_len, base_extra)
                else:
                    zi.extra = base_extra
                zout.writestr(zi, data)
                count += 1
    return count


def strip_signing_block(raw):
    i = raw.rfind(MAGIC)
    if i < 0:
        return raw
    size = struct.unpack_from("<Q", raw, i - 8)[0]
    start = i - size + 8
    return raw[:start] + raw[i + 16:]


def load_key(pk8_path, cert_pem_path):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import (
        Encoding, load_der_private_key)
    key = load_der_private_key(open(pk8_path, "rb").read(), password=None)
    cert = x509.load_pem_x509_certificate(open(cert_pem_path, "rb").read())
    return key, cert, cert.public_bytes(Encoding.DER)
