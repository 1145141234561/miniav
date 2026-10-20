"""Windows Authenticode 数字签名校验（WinVerifyTrust + CryptCATAdmin + PS 兜底）。

校验分三层：
  1. 嵌入签名：WinVerifyTrust + GENERIC_VERIFY_V2 + FILE_INFO（快，纯 native）
  2. catalog 目录签名：CryptCATAdmin 按文件哈希检索覆盖它的 .cat，
     再用 WINTRUST_CATALOG_INFO 校验（现代系统文件/驱动大多无嵌入签名）
  3. PowerShell Get-AuthenticodeSignature 批量兜底：部分机器上
     CryptCATAdminAcquireContext 会返回 ACCESS_DENIED（catalog 数据库
     子系统异常），此时 PowerShell 内置实现仍可正确校验 catalog 签名

注意 x64 下 WINTRUST_DATA 的 union 实际位于 dwUnionChoice 之后
（偏移 40，sizeof=80），与 mingw-w64 头文件一致；经探针实验证实，
照搬微软 SDK"union 在末尾"的排版会因对齐错位导致访问违例。

返回分类：
  ok        签名存在且完整可信（嵌入或 catalog）
  unsigned  无任何签名（合法软件常见，仅作提示；驱动则属高风险）
  fail      签名存在但校验失败（文件被篡改 / 证书不受信 / 已吊销等）
"""

import ctypes
import os
import sys
from ctypes import wintypes

HAS_WINTRUST = sys.platform == "win32"

# 常见返回码
_CODES = {
    0x800B0100: "无数字签名",
    0x800B0003: "无数字签名（无 SIP 认领此文件类型）",
    0x80096010: "签名摘要不匹配（文件已被篡改）",
    0x800B0109: "证书链到不受信的根",
    0x800B0101: "证书已过期",
    0x800B010C: "证书已被吊销",
    0x800B0111: "签名者被显式不信任",
    0x800B0004: "主体不受信任",
    0x800B010E: "签名无效",
    0x80092003: "文件无法读取",
    0x80092002: "签名文件损坏",
}


def _describe(code):
    return _CODES.get(code, "签名校验未通过")


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


# WINTRUST_ACTION_GENERIC_VERIFY_V2 {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
_ACTION = GUID(0x00AAC56B, 0xCD44, 0x11D0,
               (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

# DRIVER_ACTION_VERIFY {F750E6C3-3841-4CE2-9FB2-7A37D5A19705}
# 仅用作 CryptCATAdmin 的 catalog 检索子系统
_ACTION_DRIVER = GUID(0xF750E6C3, 0x3841, 0x4CE2,
                      (ctypes.c_ubyte * 8)(0x9F, 0xB2, 0x7A, 0x37, 0xD5, 0xA1, 0x97, 0x05))


class _FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.POINTER(GUID))]


class _CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("wszCatalogFile", wintypes.WCHAR * 260)]


class _CATALOG_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("dwCatalogVersion", wintypes.DWORD),
                ("pcwszCatalogFilePath", wintypes.LPCWSTR),
                ("pcwszMemberTag", wintypes.LPCWSTR),
                ("pcwszMemberFilePath", wintypes.LPCWSTR),
                ("hMemberFile", wintypes.HANDLE),
                ("cbHash", wintypes.DWORD),
                ("pbHash", ctypes.POINTER(ctypes.c_ubyte))]


class _UNION(ctypes.Union):
    _fields_ = [("pFile", ctypes.POINTER(_FILE_INFO)),
                ("pCatalog", ctypes.POINTER(_CATALOG_DATA))]


class _WINTRUST_DATA(ctypes.Structure):
    # x64 布局：union 在 dwUnionChoice 之后（偏移 40），sizeof = 80
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", wintypes.LPVOID),
                ("pSIPClientData", wintypes.LPVOID),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("u", _UNION),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD)]

    def __init__(self):
        super().__init__()
        self.cbStruct = ctypes.sizeof(self)   # 80
        self.dwUIChoice = 2                   # WTD_UI_NONE：绝不弹 UI
        self.fdwRevocationChecks = 0          # WTD_REVOKE_NONE
        self.dwStateAction = 0                # WTD_STATEACTION_IGNORE


_WTD_FILE = 1      # WTD_CHOICE_FILE
_WTD_CATALOG = 2   # WTD_CHOICE_CATALOG

_NOSIG_CODES = (0x800B0100, 0x800B0003)

if HAS_WINTRUST:
    _wt = ctypes.windll.wintrust
    _wt.WinVerifyTrust.restype = ctypes.c_long
    _wt.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID),
                                   ctypes.POINTER(_WINTRUST_DATA)]
    _wt.CryptCATAdminAcquireContext.restype = wintypes.BOOL
    _wt.CryptCATAdminAcquireContext.argtypes = [
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(GUID), wintypes.DWORD]
    _wt.CryptCATAdminReleaseContext.restype = wintypes.BOOL
    _wt.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    _wt.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL
    _wt.CryptCATAdminCalcHashFromFileHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD]
    _wt.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
    _wt.CryptCATAdminEnumCatalogFromHash.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD,
        wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    _wt.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL
    _wt.CryptCATAdminReleaseCatalogContext.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
    try:
        _wt.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
        _wt.CryptCATCatalogInfoFromContext.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_CATALOG_INFO), wintypes.DWORD]
        _HAS_CATINFO = True
    except AttributeError:
        _HAS_CATINFO = False


def _file_handle(path):
    return ctypes.windll.kernel32.CreateFileW(
        str(path), 0x80000000, 1, None, 3, 0, None)  # GENERIC_READ, share_rw, OPEN_EXISTING


# ---------------------------------------------------------------- 嵌入签名层

def _verify_embedded(path):
    """嵌入签名校验。返回 (分类, 原始码)。"""
    fi = _FILE_INFO(ctypes.sizeof(_FILE_INFO), str(path), None, None)
    wd = _WINTRUST_DATA()
    wd.dwUnionChoice = _WTD_FILE
    wd.u.pFile = ctypes.pointer(fi)
    code = _wt.WinVerifyTrust(None, ctypes.byref(_ACTION), ctypes.byref(wd)) & 0xFFFFFFFF
    if code == 0:
        return "ok", 0
    if code in _NOSIG_CODES:
        return "unsigned", code
    return "fail", code


def verify_embedded(path):
    """公开接口：仅校验嵌入签名，返回 (分类, 原始码)。"""
    if not HAS_WINTRUST:
        raise RuntimeError("数字签名校验仅支持 Windows")
    return _verify_embedded(path)


# ---------------------------------------------------------------- catalog 层

_native_catalog_ok = None  # None=未探测；True/False=CryptCATAdmin 是否可用


def _probe_native_catalog():
    global _native_catalog_ok
    if _native_catalog_ok is None:
        h = ctypes.c_void_p()
        ok = _wt.CryptCATAdminAcquireContext(ctypes.byref(h),
                                             ctypes.byref(_ACTION), 0)
        if ok:
            _wt.CryptCATAdminReleaseContext(h, 0)
        _native_catalog_ok = bool(ok)
    return _native_catalog_ok


def _verify_catalog_native(path, driver=False):
    """native catalog 校验：CryptCATAdmin 按哈希检索 .cat 后交给 wintrust 校验。

    返回 (分类, 原始码)。driver=True 时优先检索驱动子系统 catalog。
    """
    h_file = _file_handle(path)
    if h_file in (0, -1) or h_file == 0xFFFFFFFFFFFFFFFF:
        return "unsigned", 0
    try:
        buf = (ctypes.c_ubyte * 100)()
        cb = wintypes.DWORD(100)
        if not _wt.CryptCATAdminCalcHashFromFileHandle(h_file, ctypes.byref(cb),
                                                       buf, 0):
            return "unsigned", 0
        subsystems = (_ACTION_DRIVER, _ACTION) if driver else (_ACTION,)
        for sub in subsystems:
            h_admin = ctypes.c_void_p()
            if not _wt.CryptCATAdminAcquireContext(ctypes.byref(h_admin),
                                                   ctypes.byref(sub), 0):
                continue
            try:
                # 枚举所有覆盖该哈希的 catalog；句柄在枚举结束后统一释放，
                # 避免把已释放句柄当作游标传回
                prev = ctypes.c_void_p()
                opened = []
                found = None
                while True:
                    h_cat = _wt.CryptCATAdminEnumCatalogFromHash(
                        h_admin, buf, cb, 0, ctypes.byref(prev))
                    if not h_cat:
                        break
                    opened.append(h_cat)
                    prev.value = h_cat
                    if _HAS_CATINFO:
                        ci = _CATALOG_INFO()
                        ci.cbStruct = ctypes.sizeof(ci)
                        if _wt.CryptCATCatalogInfoFromContext(h_cat,
                                                              ctypes.byref(ci), 0):
                            r = _verify_catalog_member(str(path), ci.wszCatalogFile,
                                                       buf, cb.value)
                            if r[0] == "ok":
                                found = r
                                break
                for h in opened:
                    _wt.CryptCATAdminReleaseCatalogContext(h_admin, h, 0)
                if found:
                    return found
            finally:
                _wt.CryptCATAdminReleaseContext(h_admin, 0)
        return "unsigned", 0x800B0100
    finally:
        ctypes.windll.kernel32.CloseHandle(h_file)


def _verify_catalog_member(member_path, catalog_path, hash_buf, cb_hash):
    cd = _CATALOG_DATA(ctypes.sizeof(_CATALOG_DATA), 0, str(catalog_path),
                       os.path.basename(str(member_path)), str(member_path),
                       None, cb_hash,
                       ctypes.cast(hash_buf, ctypes.POINTER(ctypes.c_ubyte)))
    wd = _WINTRUST_DATA()
    wd.dwUnionChoice = _WTD_CATALOG
    wd.u.pCatalog = ctypes.pointer(cd)
    code = _wt.WinVerifyTrust(None, ctypes.byref(_ACTION), ctypes.byref(wd)) & 0xFFFFFFFF
    if code == 0:
        return "ok", 0
    if code in _NOSIG_CODES:
        return "unsigned", code
    return "fail", code


# ---------------------------------------------------------------- PS 兜底层

# catalog 层只回答一个问题：有没有可信 catalog 覆盖该文件。
# Valid -> ok；HashMismatch -> 文件与 catalog 记录不符（被篡改）；
# 其余状态（NotSigned/UnknownError/...）均视为无 catalog 覆盖 -> unsigned。
_PS_MAP = {
    "Valid": ("ok", 0),
    "HashMismatch": ("fail", 0x80096010),
}


def _ps_class(status):
    return _PS_MAP.get(status, ("unsigned", 0x800B0100))


def _ps_verify_batch(paths):
    """PowerShell Get-AuthenticodeSignature 批量校验兜底。

    CryptCATAdminAcquireContext 在部分机器上返回 ACCESS_DENIED（catalog
    数据库子系统异常），而 PowerShell 内置实现不受影响。一次进程调用
    校验全部路径。返回 {path: (Status, SignatureType)}。
    """
    import base64
    import subprocess
    esc = [str(p).replace("'", "''") for p in paths]
    script = ("$ErrorActionPreference='SilentlyContinue'\n"
              "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n"
              "$paths=@('" + "','".join(esc) + "')\n"
              "Get-AuthenticodeSignature -LiteralPath $paths | ForEach-Object { "
              "'{0}|{1}|{2}' -f $_.Path, $_.Status, $_.SignatureType }")
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    flags = 0x08000000  # CREATE_NO_WINDOW
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
            capture_output=True, timeout=180, creationflags=flags)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    res = {}
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        parts = line.rsplit("|", 2)
        if len(parts) == 3 and parts[1]:
            res[parts[0]] = (parts[1], parts[2])
    return res


def verify_catalog_batch(paths, driver=True):
    """批量 catalog 层校验（调用方先用 verify_embedded 过滤出无嵌入签名者）。

    返回 {str(path): (分类, 原始码)}。native CryptCATAdmin 可用时逐个走
    native 流程；否则合并为一次 PowerShell 调用。
    """
    paths = [str(p) for p in paths]
    out = {}
    if not paths:
        return out
    if HAS_WINTRUST and _probe_native_catalog():
        for p in paths:
            out[p] = _verify_catalog_native(p, driver=driver)
        return out
    if not HAS_WINTRUST:
        for p in paths:
            out[p] = ("unsigned", 0)
        return out
    sigs = _ps_verify_batch(paths)
    for p in paths:
        hit = sigs.get(p)
        if hit is None:  # 路径大小写/形式差异时按 basename 匹配
            base = os.path.basename(p).lower()
            hit = next((v for k, v in sigs.items()
                        if os.path.basename(k).lower() == base), None)
        if hit is None:
            out[p] = ("unsigned", 0x800B0100)
        else:
            cat, code = _ps_class(hit[0])
            out[p] = (cat, code)
    return out


# ---------------------------------------------------------------- 组合接口

def verify(path, driver=False):
    """校验文件签名（嵌入优先，catalog 回退），返回 (分类, 原始码)。

    非 Windows 抛 RuntimeError。
    """
    if not HAS_WINTRUST:
        raise RuntimeError("数字签名校验仅支持 Windows")
    cat, code = _verify_embedded(path)
    if cat != "unsigned":
        return cat, code
    cat2 = verify_catalog_batch([str(path)], driver=driver).get(str(path))
    if cat2 and cat2[0] == "ok":
        return cat2
    return cat2 or (cat, code)


def verify_driver(path):
    """驱动签名校验：嵌入签名优先；无嵌入签名时检索驱动子系统 catalog。

    大量系统驱动无嵌入签名、仅靠 .cat 目录文件签名，catalog 命中即视为 ok。
    """
    return verify(path, driver=True)


def describe(code):
    return _describe(code)
