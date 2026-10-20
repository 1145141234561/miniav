"""进程安全检查：枚举运行进程，校验文件签名/路径合法性/系统进程伪装。

纯用户态只读快照（ctypes 枚举 + 文件校验），不注入、不终止任何进程。
签名校验两阶段：嵌入签名逐个（native 快）→ catalog 批量兜底（PS）。
"""

import ctypes
import os
from ctypes import wintypes
from pathlib import Path

from .wintrust import (HAS_WINTRUST, verify_catalog_batch, verify_embedded)

# Windows 核心进程名：出现在非系统目录即高度可疑（伪装）
_CORE_NAMES = {
    "svchost.exe", "lsass.exe", "services.exe", "winlogon.exe",
    "csrss.exe", "smss.exe", "wininit.exe", "spoolsv.exe",
    "dwm.exe", "wininit.exe", "taskhostw.exe", "fontdrvhost.exe",
}
_SYS_DIRS = ("\\windows\\system32", "\\windows\\syswow64",
             "\\windows\\explorer.exe", "\\windows\\winsxs")

_TEMP_MARKS = ("\\appdata\\local\\temp", "\\windows\\temp")
_MSIX_MARK = "\\windowsapps\\"  # MSIX 打包应用无嵌入签名属正常（包级签名）

# 枚举常量
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _list_processes():
    """返回 [(pid, exe_path)]；打不开的进程自动跳过。"""
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    count = 4096
    while True:
        arr = (wintypes.DWORD * count)()
        cb = wintypes.DWORD()
        if not psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr),
                                   ctypes.byref(cb)):
            return []
        n = cb.value // ctypes.sizeof(wintypes.DWORD)
        if n < count:
            pids = arr[:n]
            break
        count *= 2
    out = []
    size = wintypes.DWORD(1024)
    buf = ctypes.create_unicode_buffer(1024)
    for pid in pids:
        if not pid:
            continue
        h = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            continue
        try:
            size.value = 1024
            if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                out.append((pid, buf.value))
        finally:
            k32.CloseHandle(h)
    return out


def scan_processes(db):
    """进程安全快照，返回 (rows, stats)。

    rows: [{pid, name, path, sig, sig_code, level, risks}]
    只查哈希与签名，不读取内容、不做内容扫描。
    """
    procs = _list_processes()
    rows = []
    windir = os.environ.get("WINDIR", r"C:\Windows").lower()

    for pid, path in procs:
        name = Path(path).name.lower()
        row = {"pid": pid, "name": Path(path).name, "path": path,
               "sig": "-", "sig_code": 0, "level": "ok", "risks": []}
        rows.append(row)
        p = path.lower()
        if name in _CORE_NAMES and not any(d in p for d in _SYS_DIRS) \
                and not p.startswith(windir + "\\"):
            row["risks"].append("核心系统进程名出现在非系统目录（疑似伪装）")
            row["level"] = "high"
        if any(m in p for m in _TEMP_MARKS):
            row["risks"].append("运行于临时目录")
            row["level"] = "high"

    # 签名库哈希快查（md5/sha1/sha256 段）
    from . import scanner
    for row in rows:
        try:
            hs = scanner.hash_all(row["path"])
        except OSError:
            continue
        for algo in ("sha256", "md5", "sha1"):
            hit = db.get("hashes", {}).get(algo, {}).get(hs.get(algo, ""))
            if hit:
                row["risks"].append(
                    f"命中签名库 {algo.upper()}: {hit.get('name', 'Unknown')}")
                row["level"] = "high"
                break

    # 两阶段签名校验
    if HAS_WINTRUST:
        embedded = {}
        for row in rows:
            try:
                embedded[id(row)] = verify_embedded(row["path"])
            except OSError:
                continue
        unsigned = [r["path"] for r in rows
                    if embedded.get(id(r), ("unsigned", 0))[0] == "unsigned"
                    and Path(r["path"]).is_file()]
        cat = verify_catalog_batch(unsigned, driver=False) if unsigned else {}
        for row in rows:
            res, code = embedded.get(id(row), ("skip", 0))
            if res == "unsigned" and row["path"] in cat:
                res, code = cat[row["path"]]
            row["sig"], row["sig_code"] = res, code
            if res == "unsigned" and row["level"] == "ok":
                if _MSIX_MARK in row["path"].lower():
                    row["sig"] = "msix"
                    row["risks"].append("MSIX 打包应用（包级签名，无嵌入签名属正常）")
                else:
                    row["risks"].append("进程映像无数字签名")
                    row["level"] = "medium"
            elif res == "fail":
                row["risks"].append("数字签名校验失败")
                row["level"] = "high"

    stats = {"total": len(rows), "unsigned": 0, "suspicious": 0, "ok": 0}
    for row in rows:
        if row["sig"] == "unsigned":
            stats["unsigned"] += 1
        if row["level"] in ("high", "medium"):
            stats["suspicious"] += 1
        elif row["level"] == "ok":
            stats["ok"] += 1
    return rows, stats


def format_report(rows, stats):
    L = [f"进程安全检查: 共 {stats['total']} 个进程 · 可疑 {stats['suspicious']} · "
         f"无签名 {stats['unsigned']}"]
    for r in rows:
        if r["level"] == "ok" and r["sig"] in ("ok", "-", "skip", "msix"):
            continue
        L.append(f"  [{r['level'].upper()}] PID {r['pid']} {r['name']}")
        L.append(f"      路径: {r['path']}")
        if r["risks"]:
            L.append("      风险: " + "; ".join(r["risks"]))
        if r["sig"] not in ("-",):
            L.append(f"      签名: {r['sig']}")
    clean = stats["total"] - sum(
        1 for r in rows
        if not (r["level"] == "ok"
                and r["sig"] in ("ok", "-", "skip", "msix")))
    L.append(f"[i] 其余 {clean} 个进程未见异常（已省略）。")
    return "\n".join(L)
