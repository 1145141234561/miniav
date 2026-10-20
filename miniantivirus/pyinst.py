"""PyInstaller CArchive 归档静态解析（只读，不解压任何条目、绝不执行）。

银狐等投递家族大量使用 PyInstaller onefile 一体式释放器。CArchive 的
TOC（Table of Contents）以明文保存在文件尾部 cookie 之前，无需解压
即可还原完整打包清单。本模块只做结构解析与高置信启发判定。

Cookie（PyInstaller 5.x/6.x，共 88 字节，位于 onefile 文件尾）：
    magic(8s) + pkgLen(!I) + tocOff(!I) + tocLen(!I) + pyver(!I) + pylibname(64s)
TOC 条目（大端）：
    entryLen(!I) + pos(!I) + cmprSize(!I) + uncmprSize(!I) + cmprsFlag(B) + type(c) + name
"""

import struct

COOKIE_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
COOKIE_SIZE = 88
ENTRY_HEADER = 18          # !IIIIBc
MAX_TOC_SIZE = 16 * 1024 * 1024   # TOC 安全预算
MAX_ENTRIES = 8192
TAIL_WINDOW = 8 * 1024 * 1024     # 大文件分段读后 TOC 落在尾部窗口内

# 归档内嵌可执行载荷的条目后缀（.dll/.pyd 属 PyInstaller 正常捆绑，不检）
_EMBEDDED_SUFFIXES = (".exe", ".scr", ".pif", ".com")


def parse_toc(tail):
    """解析一段包含 CArchive TOC + cookie 的尾部数据。

    返回 (entries, pylib)；entries 为 [(name, type_char, compressed, unc_size), ...]，
    结构不合法/非 CArchive 返回 (None, "")。

    cookie 不一定在文件尾：Authenticode 签名的 onefile exe 会在归档之后
    追加证书表，因此从尾部窗口反向搜索 cookie magic，并按
    archive_end = magic 位置 + 88 推算归档端点。pkgLen 自归档起始
    （payload 起）计至 archive_end，含 TOC 与 cookie 本身。
    """
    if len(tail) < COOKIE_SIZE + ENTRY_HEADER:
        return None, ""
    magic_pos = tail.rfind(COOKIE_MAGIC)
    if magic_pos < 0:
        return None, ""
    archive_end = magic_pos + COOKIE_SIZE
    try:
        pkg_len, toc_off, toc_len, _pyver = struct.unpack(
            "!IIII", tail[magic_pos + 8:magic_pos + 24])
    except struct.error:
        return None, ""
    pylib = tail[magic_pos + 24:magic_pos + COOKIE_SIZE].rstrip(
        b"\x00").decode("ascii", "replace")
    if toc_len == 0 or toc_len > MAX_TOC_SIZE:
        return None, ""
    toc_abs = archive_end - pkg_len + toc_off
    # TOC 必须整体落在 cookie 之前且在窗口内
    if toc_abs < 0 or toc_abs + toc_len > archive_end:
        return None, ""
    toc = tail[toc_abs:toc_abs + toc_len]
    entries, pos = [], 0
    while pos + ENTRY_HEADER <= len(toc):
        if len(entries) >= MAX_ENTRIES:
            return None, ""
        try:
            (elen,) = struct.unpack("!I", toc[pos:pos + 4])
            _pos, _csz, _usz = struct.unpack("!III", toc[pos + 4:pos + 16])
        except struct.error:
            return None, ""
        if elen < ENTRY_HEADER or pos + elen > len(toc):
            return None, ""            # TOC 损坏，宁可放弃也不误判
        cflag = toc[pos + 16]
        typ = toc[pos + 17:pos + 18].decode("ascii", "replace")
        name = toc[pos + ENTRY_HEADER:pos + elen].split(b"\x00")[0].decode(
            "utf-8", "replace")
        entries.append((name, typ, bool(cflag), _usz))
        pos += elen
    return entries, pylib


def pyinst_findings(data):
    """对文件内容窗口做 PyInstaller 结构启发（供 scanner.scan_file 挂接）。"""
    tail = data[-TAIL_WINDOW:] if len(data) > TAIL_WINDOW else data
    entries, _pylib = parse_toc(tail)
    if not entries:
        return []
    embedded = sorted({n for n, _t, _c, _s in entries
                       if n.lower().endswith(_EMBEDDED_SUFFIXES)})
    out = []
    if embedded:
        shown = ", ".join(embedded[:8]) + ("…" if len(embedded) > 8 else "")
        out.append({"name": "PyInstaller-Embedded-PE",
                    "level": "medium",
                    "detail": "PyInstaller 归档内嵌可执行载荷条目: "
                              f"{shown}（一体式释放器典型结构，需人工研判）"})
    return out
