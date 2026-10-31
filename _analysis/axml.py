#!/usr/bin/env python3
"""Парсер Android binary XML (AXML) + резолвер ресурсов из resources.arsc.

Только stdlib. Умеет:
  * читать RES_XML_TYPE (0x0003) и все чанки внутри;
  * пул строк в UTF-8 (flags & 0x100) и UTF-16LE;
  * RES_XML_RESOURCE_MAP (0x0180) — id атрибутов;
  * START/END_ELEMENT (0x0102/0x0103) со всеми атрибутами;
  * декодировать typedValue: reference/string/float/dimension/fraction/
    int dec/hex/boolean/color;
  * по --apk резолвить @0x7f...... в @type/name (+ значение для строк).

Использование:
    python3 axml.py --apk br.apk res/layout/br_new_captcha.xml
    python3 axml.py --raw --apk br.apk res/layout/br_new_captcha.xml
    python3 axml.py --pool --apk br.apk res/layout/br_new_captcha.xml
    python3 axml.py res/layout/br_new_captcha.xml      # если файл уже распакован
"""

import struct
import sys
import zipfile

# ------------------------------------------------------------------ константы

RES_STRING_POOL_TYPE       = 0x0001
RES_TABLE_TYPE             = 0x0002
RES_XML_TYPE               = 0x0003
RES_XML_START_NAMESPACE    = 0x0100
RES_XML_END_NAMESPACE      = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE   = 0x0103
RES_XML_CDATA_TYPE         = 0x0104
RES_XML_RESOURCE_MAP_TYPE  = 0x0180
RES_TABLE_PACKAGE_TYPE     = 0x0200
RES_TABLE_TYPE_TYPE        = 0x0201
RES_TABLE_TYPE_SPEC_TYPE   = 0x0202

TYPE_REFERENCE       = 0x01
TYPE_ATTRIBUTE       = 0x02
TYPE_STRING          = 0x03
TYPE_FLOAT           = 0x04
TYPE_DIMENSION       = 0x05
TYPE_FRACTION        = 0x06
TYPE_DYNAMIC_REF     = 0x07
TYPE_INT_DEC         = 0x10
TYPE_INT_HEX         = 0x11
TYPE_INT_BOOLEAN     = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1c
TYPE_INT_COLOR_RGB8  = 0x1d
TYPE_INT_COLOR_ARGB4 = 0x1e
TYPE_INT_COLOR_RGB4  = 0x1f

DIM_UNITS  = {0: "px", 1: "dip", 2: "sp", 3: "pt", 4: "in", 5: "mm"}
FRAC_UNITS = {0: "%", 1: "%p"}

# Gravity: AXIS_X = младшие 3 бита, AXIS_Y = биты 4..6
GRAVITY_X = {0x01: "center_horizontal", 0x02: "left", 0x03: "left",
             0x04: "right", 0x05: "right", 0x06: "fill_horizontal",
             0x07: "fill_horizontal"}
GRAVITY_Y = {0x10: "center_vertical", 0x20: "top", 0x30: "top",
             0x40: "bottom", 0x50: "bottom", 0x60: "fill_vertical",
             0x70: "fill_vertical"}

INPUT_CLASS = {0x00: "NULL", 0x01: "TEXT", 0x02: "NUMBER", 0x03: "PHONE",
               0x04: "DATETIME", 0x81: "TEXT"}

IME_ACTION = {0: "UNSPECIFIED", 1: "GO", 2: "SEARCH", 3: "SEND", 4: "NEXT",
              5: "DONE", 6: "PREVIOUS"}

# EditorInfo.IME_FLAG_* (старшие биты imeOptions)
IME_FLAGS = [(0x10000000, "NO_PERSONALIZED_LEARNING"),
             (0x08000000, "NAVIGATE_NEXT"),
             (0x04000000, "NAVIGATE_PREVIOUS"),
             (0x02000000, "NO_FULLSCREEN"),
             (0x01000000, "NO_EXTRACT_UI"),
             (0x00800000, "NO_ENTER_ACTION"),
             (0x40000000, "FLAG_NO_ENTER_ACTION"),
             (0x80000000, "FORCE_ASCII")]

# InputType.TYPE_TEXT_FLAG_* / TYPE_TEXT_VARIATION_*
INPUT_FLAGS = [(0x00001000, "CAP_CHARACTERS"),
               (0x00002000, "CAP_WORDS"),
               (0x00004000, "CAP_SENTENCES"),
               (0x00008000, "AUTO_CORRECT"),
               (0x00010000, "AUTO_COMPLETE"),
               (0x00020000, "MULTI_LINE"),
               (0x00040000, "IME_MULTI_LINE"),
               (0x00080000, "NO_SUGGESTIONS"),
               (0x00100000, "VISIBLE_PASSWORD"),
               (0x01000000, "TYPE_NULL")]

INPUT_VARIATION = {0x00000000: "normal", 0x00100000: "uri", 0x00200000: "email_address",
                   0x00300000: "email_subject", 0x00400000: "short_message",
                   0x00500000: "long_message", 0x00600000: "person_name",
                   0x00700000: "postal_address", 0x00800000: "password",
                   0x00900000: "visible_password", 0x00a00000: "web_edit_text",
                   0x00b00000: "filter", 0x00c00000: "phonetic",
                   0x00d00000: "web_email_address", 0x00e00000: "web_password",
                   0x01000000: "number_password", 0x01100000: "number_visible_password"}


TEXT_STYLE = {0: "normal", 1: "bold", 2: "italic", 3: "bold|italic"}

NS_PREFIX = {
    "http://schemas.android.com/apk/res/android": "android",
    "http://schemas.android.com/apk/res-auto": "app",
    "http://schemas.android.com/tools": "tools",
    "http://schemas.android.com/apk/res/android/res-auto": "app",
}


def ns_prefix(uri):
    if uri is None:
        return None
    return NS_PREFIX.get(uri, uri)


def signed32(v):
    return v - 0x100000000 if v & 0x80000000 else v


def complex_to_float(data):
    """Android упаковывает dimension/fraction как fixed-point с radix в битах 4..5.

    complexToFloat: (data & 0xFFFFFF00) * RADIX_MULTS[(data >> 4) & 3].
    """
    radix = (data >> 4) & 3
    mult = (1.0 / 256.0, 1.0 / 32768.0, 1.0 / (1 << 23), 1.0 / (1 << 31))[radix]
    return signed32(data & 0xFFFFFF00) * mult


# ------------------------------------------------------------------ чанки

class Chunk:
    __slots__ = ("type", "header_size", "size", "off")

    def __init__(self, type_, header_size, size, off):
        self.type = type_
        self.header_size = header_size
        self.size = size
        self.off = off

    def __repr__(self):
        return "<Chunk 0x%04x hs=%d size=%d @%d>" % (
            self.type, self.header_size, self.size, self.off)


def iter_chunks(data, start, end):
    off = start
    while off + 8 <= end:
        ctype, hsize, size = struct.unpack_from("<HHI", data, off)
        if size < 8 or off + size > end:
            break
        yield Chunk(ctype, hsize, size, off)
        off += size


class StringPool:
    """RES_STRING_POOL_TYPE.

    В UTF-8 режиме AOSP пишет ДВЕ длины: число UTF-16-символов, затем число
    байт UTF-8 (обе — u8, с 0x80-расширением). В UTF-16 — одна длина u16
    (с 0x8000-расширением).
    """

    def __init__(self, data, chunk):
        base = chunk.off
        (self.string_count, self.style_count, self.flags,
         self.strings_start, self.styles_start) = struct.unpack_from("<5I", data, base + 8)
        self.utf8 = bool(self.flags & 0x100)
        self.offsets = list(struct.unpack_from(
            "<%dI" % self.string_count, data, base + chunk.header_size))
        self.data = data
        self.base = base

    @staticmethod
    def _len8(d, off):
        n = d[off]
        off += 1
        if n & 0x80:
            n = ((n & 0x7F) << 8) | d[off]
            off += 1
        return n, off

    def _decode(self, off):
        d = self.data
        if self.utf8:
            _u16len, off = self._len8(d, off)
            u8len, off = self._len8(d, off)
            return d[off:off + u8len].decode("utf-8", "replace")
        n = struct.unpack_from("<H", d, off)[0]
        off += 2
        if n & 0x8000:
            n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", d, off)[0]
            off += 2
        return d[off:off + n * 2].decode("utf-16-le", "replace")

    def get(self, idx):
        if idx == 0xFFFFFFFF or idx >= self.string_count:
            return None
        try:
            return self._decode(self.base + self.strings_start + self.offsets[idx])
        except Exception:
            return None

    def __len__(self):
        return self.string_count


# ------------------------------------------------------------------ arsc

class ResTable:
    """Минимальный разбор resources.arsc: id ресурса -> type/key и значение."""

    def __init__(self, data):
        self.d = data
        self.entries = {}     # rid -> (type_name, key, dtype, data, is_default)
        self.global_strings = None
        ftype, hsize, fsize = struct.unpack_from("<HHI", data, 0)
        if ftype != RES_TABLE_TYPE:
            return
        for ch in iter_chunks(data, hsize, min(fsize, len(data))):
            if ch.type == RES_STRING_POOL_TYPE and self.global_strings is None:
                self.global_strings = StringPool(data, ch)
            elif ch.type == RES_TABLE_PACKAGE_TYPE:
                self._package(ch)

    def _package(self, ch):
        d = self.d
        pkg_id = struct.unpack_from("<I", d, ch.off + 8)[0]
        type_strings_off, _last_type, key_strings_off, _last_key = struct.unpack_from(
            "<4I", d, ch.off + 268)
        type_pool = StringPool(d, Chunk(RES_STRING_POOL_TYPE, 28,
                                        struct.unpack_from("<I", d, ch.off + type_strings_off + 4)[0],
                                        ch.off + type_strings_off))
        key_pool = StringPool(d, Chunk(RES_STRING_POOL_TYPE, 28,
                                       struct.unpack_from("<I", d, ch.off + key_strings_off + 4)[0],
                                       ch.off + key_strings_off))
        for sub in iter_chunks(d, ch.off + ch.header_size, ch.off + ch.size):
            if sub.type != RES_TABLE_TYPE_TYPE:
                continue
            type_id = d[sub.off + 8]
            entry_count, entries_start = struct.unpack_from("<2I", d, sub.off + 12)
            cfg_size = struct.unpack_from("<I", d, sub.off + 20)[0]
            cfg = d[sub.off + 20:sub.off + 20 + cfg_size]
            is_default = not any(cfg[4:])
            type_name = type_pool.get(type_id - 1) or ("type%d" % type_id)
            offs_base = sub.off + sub.header_size
            for i in range(entry_count):
                eoff = struct.unpack_from("<I", d, offs_base + i * 4)[0]
                if eoff == 0xFFFFFFFF:
                    continue
                p = sub.off + entries_start + eoff
                esize, eflags, ekey = struct.unpack_from("<HHI", d, p)
                key = key_pool.get(ekey) or ("entry%d" % i)
                rid = (pkg_id << 24) | (type_id << 16) | i
                dtype = data_ = None
                if not (eflags & 0x0001):  # не bag
                    vsize, vres0, dtype, data_ = struct.unpack_from("<HBBI", d, p + esize)
                prev = self.entries.get(rid)
                if prev is None or (is_default and not prev[4]):
                    self.entries[rid] = (type_name, key, dtype, data_, is_default)

    def qualname(self, rid):
        e = self.entries.get(rid)
        if not e:
            return None
        return "%s/%s" % (e[0], e[1])

    def value(self, rid):
        """Строковое значение ресурса, если он строковый."""
        e = self.entries.get(rid)
        if not e or e[2] is None:
            return None
        dtype, data_ = e[2], e[3]
        if dtype == TYPE_STRING and self.global_strings:
            return self.global_strings.get(data_)
        if dtype == TYPE_INT_BOOLEAN:
            return "true" if data_ else "false"
        if dtype == TYPE_INT_COLOR_ARGB8:
            return "#%08X" % data_
        if dtype == TYPE_REFERENCE:
            return "@0x%08x" % data_
        return None

    def describe(self, rid):
        q = self.qualname(rid)
        v = self.value(rid)
        if q is None:
            return "@0x%08x" % rid
        if q.startswith("id/"):
            return "@" + q
        if v is not None:
            return "@%s = %r" % (q, v)
        return "@" + q


# ------------------------------------------------------------------ значения

class ValueFormatter:
    def __init__(self, res=None):
        self.res = res

    def ref(self, rid):
        if self.res is not None:
            return self.res.describe(rid)
        return "@0x%08x" % rid

    def __call__(self, attr_name, dtype, data, pool):
        if dtype == TYPE_STRING:
            s = pool.get(data) if pool else None
            return repr(s) if s is not None else "string#%d" % data
        if dtype == TYPE_REFERENCE:
            if data == 0:
                return "@null"
            if data == 0x01000000:
                return "@empty"
            return self.ref(data)
        if dtype == TYPE_ATTRIBUTE:
            return "?0x%08x" % data
        if dtype == TYPE_DYNAMIC_REF:
            return "@dynamic/0x%08x" % data
        if dtype == TYPE_FLOAT:
            return "%g" % struct.unpack("<f", struct.pack("<I", data))[0]
        if dtype == TYPE_DIMENSION:
            return "%g%s" % (complex_to_float(data), DIM_UNITS.get(data & 0xF, "?"))
        if dtype == TYPE_FRACTION:
            return "%g%s" % (complex_to_float(data) * 100.0, FRAC_UNITS.get(data & 0xF, "%"))
        if dtype == TYPE_INT_BOOLEAN:
            return "true" if data else "false"
        if dtype == TYPE_INT_COLOR_ARGB8:
            return "#%08X" % data
        if dtype == TYPE_INT_COLOR_RGB8:
            return "#%06X" % (data & 0xFFFFFF)
        if dtype == TYPE_INT_COLOR_ARGB4:
            return "#%X%X%X%X" % ((data >> 12) & 0xF, (data >> 8) & 0xF,
                                  (data >> 4) & 0xF, data & 0xF)
        if dtype == TYPE_INT_COLOR_RGB4:
            return "#%X%X%X" % ((data >> 8) & 0xF, (data >> 4) & 0xF, data & 0xF)
        if dtype == TYPE_INT_HEX:
            return "0x%08x" % data
        if dtype == TYPE_INT_DEC:
            v = signed32(data)
            if attr_name in ("layout_width", "layout_height", "width", "height",
                             "minWidth", "minHeight", "maxWidth", "maxHeight"):
                if v == -1:
                    return "MATCH_PARENT (-1)"
                if v == -2:
                    return "WRAP_CONTENT (-2)"
            return str(v)
        return "0x%08x (type 0x%02x)" % (data, dtype)


def describe_gravity(v):
    if v == 0:
        return "none"
    rel = bool(v & 0x00800000)
    parts = []
    x = v & 0x07
    if x:
        name = GRAVITY_X.get(x)
        if name == "left" and rel:
            name = "start"
        if name == "right" and rel:
            name = "end"
        parts.append(name or "x=0x%x" % x)
    y = v & 0x70
    if y:
        parts.append(GRAVITY_Y.get(y) or "y=0x%x" % y)
    if v & 0x800000:
        parts.append("display_clip_vertical")
    if v & 0x400000:
        parts.append("display_clip_horizontal")
    return "|".join(parts) if parts else "0x%08x" % v


def describe_input_type(v):
    cls = INPUT_CLASS.get(v & 0x0F, "class0x%02x" % (v & 0x0F))
    bits = [name for bit, name in INPUT_FLAGS if v & bit]
    variation = INPUT_VARIATION.get(v & 0x00F00000)
    out = "TYPE_CLASS_" + cls if cls != "NULL" else "TYPE_NULL"
    if bits:
        out += " | " + " | ".join("TYPE_TEXT_FLAG_" + b for b in bits)
    if variation:
        out += " | variation=" + variation
    return "%s (0x%08x)" % (out, v)


def describe_ime(v):
    action = IME_ACTION.get(v & 0xFF, "0x%x" % (v & 0xFF))
    flags = [name for bit, name in IME_FLAGS if v & bit]
    return "action=IME_ACTION_%s%s" % (action, (" | " + " | ".join(flags)) if flags else "")


# ------------------------------------------------------------------ дерево

class Attr:
    __slots__ = ("ns", "name", "raw", "dtype", "data", "res_id", "value", "display")

    def __init__(self, ns, name, raw, dtype, data, res_id, value, display):
        self.ns = ns
        self.name = name
        self.raw = raw
        self.dtype = dtype
        self.data = data
        self.res_id = res_id
        self.value = value
        self.display = display

    def label(self):
        p = ns_prefix(self.ns)
        if p:
            return "%s:%s" % (p, self.name)
        return self.name


class Node:
    __slots__ = ("tag", "attrs", "children", "line", "parent")

    def __init__(self, tag, attrs, line, parent):
        self.tag = tag
        self.attrs = attrs
        self.children = []
        self.line = line
        self.parent = parent

    def attr(self, name):
        for a in self.attrs:
            if a.name == name:
                return a
        return None

    def val(self, name, default=None):
        a = self.attr(name)
        return a.display if a is not None else default

    def walk(self):
        yield self
        for c in self.children:
            for n in c.walk():
                yield n


def parse_axml(data, res=None):
    if len(data) < 8:
        raise ValueError("файл слишком мал")
    ftype, fhsize, fsize = struct.unpack_from("<HHI", data, 0)
    if ftype != RES_XML_TYPE:
        raise ValueError("не AXML: тип 0x%04x" % ftype)

    fmt = ValueFormatter(res)
    pool = None
    res_map = []
    root = None
    stack = []
    namespaces = []

    for ch in iter_chunks(data, fhsize, min(fsize, len(data))):
        if ch.type == RES_STRING_POOL_TYPE:
            pool = StringPool(data, ch)
        elif ch.type == RES_XML_RESOURCE_MAP_TYPE:
            n = (ch.size - ch.header_size) // 4
            res_map = list(struct.unpack_from("<%dI" % n, data, ch.off + ch.header_size))
        elif ch.type == RES_XML_START_NAMESPACE:
            _line, _c, prefix, uri = struct.unpack_from("<4I", data, ch.off + 8)
            namespaces.append((pool.get(prefix) if pool else None,
                               pool.get(uri) if pool else None))
        elif ch.type == RES_XML_START_ELEMENT_TYPE:
            base = ch.off
            (line, _comment, _ns_idx, name_idx,
             attr_start, attr_size, attr_count,
             _id_idx, _class_idx, _style_idx) = struct.unpack_from("<4I6H", data, base + 8)
            tag = pool.get(name_idx) if pool else None
            attrs = []
            aoff = base + ch.header_size + attr_start
            for i in range(attr_count):
                p = aoff + i * attr_size
                a_ns, a_name, a_raw = struct.unpack_from("<III", data, p)
                _vsize, _vres0, v_type, v_data = struct.unpack_from("<HBBI", data, p + 12)
                ns = pool.get(a_ns) if (pool and a_ns != 0xFFFFFFFF) else None
                name = pool.get(a_name) if pool else None
                rid = res_map[i] if i < len(res_map) else 0
                if not name:
                    name = "attr_0x%08x" % rid
                raw = pool.get(a_raw) if (pool and a_raw != 0xFFFFFFFF) else None
                display = fmt(name, v_type, v_data, pool)
                if name == "gravity" or name == "layout_gravity":
                    if v_type in (TYPE_INT_HEX, TYPE_INT_DEC):
                        display += "  (%s)" % describe_gravity(v_data)
                elif name == "orientation" and v_type in (TYPE_INT_DEC, TYPE_INT_HEX):
                    display += "  (%s)" % ("vertical" if v_data else "horizontal")
                elif name == "visibility" and v_type in (TYPE_INT_DEC, TYPE_INT_HEX):
                    display += "  (%s)" % {0: "visible", 1: "invisible",
                                           2: "gone"}.get(v_data, "?")
                elif name == "inputType" and v_type in (TYPE_INT_HEX, TYPE_INT_DEC):
                    display += "  (%s)" % describe_input_type(v_data)
                elif name == "imeOptions" and v_type in (TYPE_INT_HEX, TYPE_INT_DEC):
                    display += "  (%s)" % describe_ime(v_data)
                elif name == "textStyle" and v_type in (TYPE_INT_DEC, TYPE_INT_HEX):
                    display += "  (%s)" % TEXT_STYLE.get(v_data, "?")
                attrs.append(Attr(ns, name, raw, v_type, v_data, rid, display, display))
            node = Node(tag, attrs, line, stack[-1] if stack else None)
            if stack:
                stack[-1].children.append(node)
            else:
                root = node
            stack.append(node)
        elif ch.type == RES_XML_END_ELEMENT_TYPE:
            if stack:
                stack.pop()
    return root, pool, res_map, namespaces


def dump_tree(node, out=sys.stdout, indent=0, raw=False):
    pad = "  " * indent
    out.write("%s<%s>   ; line %d\n" % (pad, node.tag, node.line))
    for a in node.attrs:
        extra = ""
        if raw:
            extra = "   [type=0x%02x data=0x%08x rid=0x%08x]" % (a.dtype, a.data, a.res_id)
        out.write("%s    %-30s = %s%s\n" % (pad, a.label(), a.value, extra))
    for c in node.children:
        dump_tree(c, out, indent + 1, raw)


def load_apk(path):
    z = zipfile.ZipFile(path)
    res = None
    if "resources.arsc" in z.namelist():
        res = ResTable(z.read("resources.arsc"))
    return z, res


def main(argv):
    raw = "--raw" in argv
    pool_dump = "--pool" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 1

    res = None
    if len(args) >= 2 and args[0].endswith(".apk"):
        apk, member = args[0], args[1]
        z, res = load_apk(apk)
        data = z.read(member)
        print("// %s :: %s (%d байт)" % (apk, member, len(data)))
    elif "::" in args[0]:
        apk, member = args[0].split("::", 1)
        z, res = load_apk(apk)
        data = z.read(member)
        print("// %s :: %s (%d байт)" % (apk, member, len(data)))
    else:
        data = open(args[0], "rb").read()
        print("// %s (%d байт)" % (args[0], len(data)))

    root, pool, res_map, ns = parse_axml(data, res)
    if pool_dump and pool:
        for i in range(len(pool)):
            print("%4d: %r" % (i, pool.get(i)))
        print()
    print("// пул строк: %d | id в resource map: %d | namespaces: %s"
          % (len(pool) if pool else 0, len(res_map),
             ", ".join("%s=%s" % (p, u) for p, u in ns)))
    print()
    if root is None:
        print("// дерево пустое")
        return 1
    dump_tree(root, sys.stdout, 0, raw)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
