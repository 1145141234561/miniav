"""启动项安全检查：注册表 Run/RunOnce、启动文件夹、计划任务、服务。

对每个启动项解析可执行路径，校验文件存在性、数字签名（嵌入签名 →
catalog 批量兜底）、落位目录可疑度，输出风险标记。
纯注册表/文件系统读取，绝不执行任何启动项。
"""

import os
import re
import winreg
from pathlib import Path

from .wintrust import (HAS_WINTRUST, verify_catalog_batch, verify_embedded)

_RUN_KEYS = [
    ("HKLM\\...\\Run", winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Run", 0),
    ("HKLM\\...\\RunOnce", winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 0),
    ("HKLM(WOW64)\\...\\Run", winreg.HKEY_LOCAL_MACHINE,
     r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
     winreg.KEY_WOW64_32KEY),
    ("HKCU\\...\\Run", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run", 0),
    ("HKCU\\...\\RunOnce", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 0),
]

_TASKS_DIR = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "Tasks"
_SVCS_KEY = r"SYSTEM\CurrentControlSet\Services"

_TEMP_MARKS = ("\\appdata\\local\\temp", "\\temp\\", "\\tmp\\")
_APPDATA_MARK = "\\appdata\\roaming"
_PROGDATA_MARK = "\\programdata"


def _parse_command(cmd):
    """从命令串提取可执行路径（处理引号、带空格路径、环境变量）。"""
    cmd = cmd.strip()
    if not cmd:
        return None
    if cmd.startswith('"'):
        return os.path.expandvars(cmd[1:].split('"', 1)[0] or "") or None
    cmd = os.path.expandvars(cmd)
    parts = cmd.split(" ")
    cand = parts[0]
    for nxt in parts[1:6]:
        if Path(cand).exists() or ("~" in cand):
            break
        if nxt.lower().startswith(("/", "-")):
            break
        if Path(cand + " " + nxt).exists():
            cand = cand + " " + nxt
            break
        cand = cand + " " + nxt
    # 相对路径（服务 ImagePath 常见形态）：相对 WINDIR 解析
    if cand and ":" not in cand and not cand.startswith("\\\\"):
        alt = Path(os.environ.get("WINDIR", r"C:\Windows")) / cand
        if alt.is_file():
            return str(alt)
    return cand or None


def _risk_level(path):
    """按落位目录给出基础风险：'high'/'medium'/None。"""
    p = str(path).lower()
    if any(m in p for m in _TEMP_MARKS):
        return "high"
    if _APPDATA_MARK in p or p.startswith(_PROGDATA_MARK):
        return "medium"
    return None


def _lnk_target(data):
    """从 .lnk 字节流提取内嵌的可执行路径（UTF-16 视图正则）。"""
    text = data.decode("utf-16-le", "ignore") + data.decode("latin-1", "ignore")
    m = re.search(r"[A-Za-z]:\\[^\x00\r\n\"<>|]{2,}?\.(?:exe|dll|bat|cmd|ps1)",
                  text, re.I)
    return m.group(0) if m else None


def _reg_values(root, sub, extra):
    """读取一个 Run 键的全部值，返回 [(名称, 命令串)]。"""
    out = []
    try:
        with winreg.OpenKey(root, sub, 0, winreg.KEY_READ | extra) as k:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                if isinstance(val, str):
                    out.append((name, val))
                i += 1
    except OSError:
        pass
    return out


def scan_autoruns():
    """全量启动项检查，返回 (rows, stats)。

    rows: [{loc, name, cmd, path, exists, sig, sig_code, level, risks}]
    stats: {total, missing, unsigned, suspicious, ok}
    """
    rows = []
    pending = []  # (row_key, path) 供 catalog 批量校验

    def add_row(loc, name, cmd, path):
        row = {"loc": loc, "name": name, "cmd": cmd, "path": path,
               "exists": None, "sig": "-", "sig_code": 0,
               "level": "ok", "risks": []}
        rows.append(row)
        return row

    def finalize(row, exists, is_pe):
        """按存在性/落位/PE 属性给出风险与级别（签名结果后补）。"""
        if exists is False:
            row["risks"].append("目标文件缺失")
            row["level"] = max_risk(row["level"], "low")
        path = row["path"]
        r = _risk_level(path) if path else None
        if r == "high":
            row["risks"].append("位于临时目录（常见恶意持久化落位）")
            row["level"] = max_risk(row["level"], "high")
        elif r == "medium":
            row["risks"].append("位于非常规持久化目录")
            row["level"] = max_risk(row["level"], "medium")
        if is_pe:
            pending.append((id(row), path))

    # ---- 注册表 Run / RunOnce ----
    for loc, root, sub, extra in _RUN_KEYS:
        for name, cmd in _reg_values(root, sub, extra):
            path = _parse_command(cmd)
            exists = Path(path).is_file() if path else None
            row = add_row(loc, name, cmd, path)
            row["exists"] = exists
            finalize(row, exists, bool(path))

    # ---- 启动文件夹 ----
    for label, d in (
            ("用户启动文件夹", Path(os.environ.get("APPDATA", ""))
             / "Microsoft/Windows/Start Menu/Programs/Startup"),
            ("公共启动文件夹", Path(os.environ.get("PROGRAMDATA", ""))
             / "Microsoft/Windows/Start Menu/Programs/Startup")):
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if f.suffix.lower() not in (".lnk", ".exe", ".bat", ".cmd",
                                        ".ps1", ".vbs", ".jse", ".js"):
                continue
            target, is_pe = None, False
            if f.suffix.lower() == ".lnk" and f.stat().st_size < 64 * 1024:
                try:
                    target = _lnk_target(f.read_bytes())
                    is_pe = bool(target)
                except OSError:
                    pass
            elif f.suffix.lower() in (".exe", ".bat", ".cmd", ".ps1", ".vbs"):
                target = str(f)
                is_pe = f.suffix.lower() == ".exe"
            row = add_row(label, f.name, target or f"{f.name}（未解析）", target)
            row["exists"] = Path(target).is_file() if target else None
            if target is None:
                row["risks"].append("快捷方式目标未解析（人工复核）")
                row["level"] = max_risk(row["level"], "low")
            finalize(row, row["exists"], is_pe)

    # ---- 计划任务（仅第三方：跳过 \Microsoft\ 命名空间） ----
    if _TASKS_DIR.is_dir():
        for f in sorted(_TASKS_DIR.rglob("*")):
            if not f.is_file() or "\\microsoft\\" in str(f).lower():
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")[:64 * 1024]
            except OSError:
                continue
            cmds = re.findall(r"<Command>([^<]{4,260})</Command>", text)
            for cmd in cmds:
                path = _parse_command(cmd.strip())
                if not path:
                    continue
                exists = Path(path).is_file()
                row = add_row(f"计划任务 {f.parent.name}\\{f.stem}",
                              f.stem, cmd.strip(), path)
                finalize(row, exists, True)

    # ---- 服务（只看 .exe 非系统目录的候选，控制规模） ----
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SVCS_KEY) as sk:
            i = 0
            while True:
                try:
                    svc = winreg.EnumKey(sk, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(sk, svc) as k:
                        img, _t = winreg.QueryValueEx(k, "ImagePath")
                except OSError:
                    continue
                if not isinstance(img, str):
                    continue
                path = _parse_command(img)
                if not path or not path.lower().endswith(".exe"):
                    continue
                windir = os.environ.get("WINDIR", r"C:\Windows").lower()
                if windir in path.lower():
                    continue  # 系统目录服务不逐条报告
                exists = Path(path).is_file()
                row = add_row("服务", svc, img, path)
                finalize(row, exists, True)
    except OSError:
        pass

    # ---- 签名校验：嵌入签名逐个（native 快）→ catalog 批量兜底 ----
    if HAS_WINTRUST:
        embedded = {}
        for key, path in pending:
            if path and Path(path).is_file():
                embedded[key] = verify_embedded(path)
        unsigned_paths = [p for key, p in pending
                          if embedded.get(key, ("unsigned", 0))[0] == "unsigned"
                          and p and Path(p).is_file()]
        cat = verify_catalog_batch(unsigned_paths, driver=False) \
            if unsigned_paths else {}
        for row in rows:
            key = id(row)
            if key in embedded:
                cat_res, code = embedded[key]
                if cat_res == "unsigned" and str(row["path"]) in cat:
                    cat_res, code = cat[str(row["path"])]
                _apply_sig(row, cat_res, code)
    else:
        for row in rows:
            if row["path"]:
                row["sig"] = "skip"

    stats = {"total": len(rows), "missing": 0, "unsigned": 0,
             "suspicious": 0, "ok": 0}
    for row in rows:
        if row["level"] in ("high", "medium", "low"):
            stats["suspicious"] += 1
        if row["exists"] is False:
            stats["missing"] += 1
        if row["sig"] == "unsigned":
            stats["unsigned"] += 1
        if row["level"] == "ok" and row["sig"] in ("ok", "-", "skip"):
            stats["ok"] += 1
    return rows, stats


def _apply_sig(row, cat_res, code):
    row["sig"], row["sig_code"] = cat_res, code
    if cat_res == "unsigned" and row["level"] == "ok":
        row["risks"].append("PE 无数字签名")
        row["level"] = "medium"
    elif cat_res == "fail":
        row["risks"].append("数字签名校验失败")
        row["level"] = "high"
    elif cat_res == "ok" and row["level"] in ("low", "medium") and \
            not any("临时" in r for r in row["risks"]):
        row["level"] = max_risk(row["level"], "low")
        row["risks"].append("目录非常规但有有效签名")


def max_risk(a, b):
    order = {"ok": 0, "low": 1, "medium": 2, "high": 3}
    return a if order.get(a, 0) >= order.get(b, 0) else b


def format_report(rows, stats):
    L = [f"启动项检查: 共 {stats['total']} 项 · 可疑 {stats['suspicious']} · "
         f"无签名 {stats['unsigned']} · 缺失 {stats['missing']}"]
    for r in rows:
        if r["level"] == "ok" and r["sig"] in ("ok", "-", "skip") \
                and r["exists"] is not False:
            continue
        L.append(f"  [{r['level'].upper()}] {r['loc']} \\ {r['name']}")
        L.append(f"      命令: {r['cmd']}")
        if r["risks"]:
            L.append("      风险: " + "; ".join(r["risks"]))
        if r["sig"] not in ("-",):
            L.append(f"      签名: {r['sig']}")
    clean = stats["total"] - sum(
        1 for r in rows
        if not (r["level"] == "ok" and r["sig"] in ("ok", "-", "skip")
                and r["exists"] is not False))
    L.append(f"[i] 其余 {clean} 项未见异常（已省略）。")
    return "\n".join(L)
