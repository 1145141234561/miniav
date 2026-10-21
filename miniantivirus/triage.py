"""快速分诊（triage）：新样本自动化静态分析。

流程：解包（zip/rar/tar/7z）→ 立即读入内存（抗 Defender 删除竞态）
→ 多层解码（编码探测 / 行反转检测 / deobf 链）→ 行为串分类提取
→ IOC 汇总 → MiniAV 引擎扫描 → 控制台摘要 + JSON 报告。

红线：纯数据操作，绝不执行、解释或派生任何样本内容。

用法：
    python -m miniantivirus.triage <样本路径> [--out 报告.json] [--emu]
"""

import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAX_TOTAL = 64 * 1024 * 1024   # 解包总预算
MAX_FILES = 256                # 条目数上限
MAX_TEXT = 4 * 1024 * 1024     # 文本解码上限
TEMP = Path(tempfile.gettempdir())

# 行为串分类词典（还原视图上统计）
BEHAVIOR = {
    "感染/寄生": ["CopyFile", "CopyFolder", "GetExtensionName", "FileSystemObject",
                  "ScriptFullName", "OpenTextFile", "CreateTextFile", "Attributes",
                  "Hidden", "autorun", "inf", "Infect"],
    "执行/进程": ["WScript.Shell", "Shell.Application", ".Run(", "cmd /c", "cmd.exe",
                  "subprocess", "os.system", "Invoke-Expression", "IEX ", "WinExec",
                  "CreateProcess", "ShellExecute"],
    "网络/下载": ["XMLHTTP", "ADODB.Stream", "URLDownloadToFile", "WebClient",
                  "Invoke-WebRequest", "urllib", "requests.get", "socket.",
                  "DownloadFile", "InternetOpen"],
    "持久化": ["RegWrite", "CurrentVersion\\Run", "Startup", "schtasks",
               "reg add", "TaskScheduler", "RunOnce"],
    "收集/窃取": ["id_rsa", "authorized_keys", "Saved Passwords", "Login Data",
                  "cookies", "WebBrowserPassView", "ClipBoard"],
    "反分析": ["sbiedll", "vmware", "vbox", "vmtoolsd", "Sandboxie",
               "GetAsyncKeyState", "IsDebuggerPresent", "rdtsc"],
    "注入/内存": ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
                  "SetThreadContext", "SuspendThread", "ResumeThread",
                  "VirtualProtect", "LoadLibrary", "GetProcAddress"],
}

_URL = re.compile(r"https?://[\x21-\x7e]{6,}")
_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9][a-z0-9-]{1,62}\.)+"
                     r"(?:com|net|org|io|cn|top|xyz|cc|me|info|ru|su|tk|biz|online|site|shop)\b",
                     re.I)

_SCRIPT_KEYS = ["CreateObject", "WScript", "FileSystemObject", "Set-Item", "Invoke",
                 "Function", "Sub ", "RegWrite", "cmdlet", "echo ", "Copy-Item",
                 "Set ", "Call ", "End If", "Then", "Loop", "Dim ", "If "]


def _extract(archive, dest):
    """解包到 dest，返回 (成功, 错误信息)。zip 用 zipfile，其余借 tar.exe。"""
    data = archive.read_bytes()[:8]
    try:
        if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
            import zipfile
            with zipfile.ZipFile(archive) as zf:
                infos = [i for i in zf.infolist() if not i.is_dir()][:MAX_FILES]
                total = 0
                for i in infos:
                    total += i.file_size
                    if total > MAX_TOTAL:
                        return False, "解包预算超限（疑似压缩炸弹）"
                    target = dest / Path(i.filename).name
                    target.write_bytes(zf.read(i))
            return True, ""
        r = subprocess.run(["tar", "-xf", str(archive), "-C", str(dest)],
                           capture_output=True, timeout=180)
        return r.returncode == 0, r.stderr.decode("utf-8", "ignore")[:200]
    except Exception as exc:
        return False, str(exc)[:200]


def _decode_views(data):
    """生成解码视图列表 [(标签, 文本)]：编码探测 + 行/整体反转检测。"""
    views = []
    enc_used = None
    for enc in ("utf-8", "gbk", "utf-16-le"):
        try:
            blob = data if len(data) % 2 == 0 else data[:-1]
            text = data.decode(enc) if enc != "utf-16-le" else blob.decode(enc)
            if text.count("\x00") < len(text) / 8:
                views.append((f"原文({enc})", text))
                enc_used = enc
                break
        except (UnicodeDecodeError, ValueError):
            continue
    if enc_used is None:
        text = data.decode("gbk", "replace")   # 兜底：混淆流常含非法 GBK 序列
        if text.strip():
            views.append(("原文(兜底gbk)", text))
    if not views:
        return views

    lines = views[0][1].splitlines()
    if not lines:
        return views

    def _key_score(ls):
        return sum(1 for ln in ls for k in _SCRIPT_KEYS if k in ln)

    base = _key_score(lines)
    rev_lines = [ln[::-1] for ln in lines]
    if _key_score(rev_lines) > base * 2 and _key_score(rev_lines) >= 3:
        views.append(("行反转还原", "\n".join(rev_lines)))
    whole_rev = views[0][1][::-1]
    if _key_score(whole_rev.splitlines()) > base * 2 and _key_score(whole_rev.splitlines()) >= 3:
        views.append(("整体反转还原", whole_rev))
    return views


def _behavior_hits(text):
    hits = {}
    for cat, keys in BEHAVIOR.items():
        found = sorted({k for k in keys if k in text})
        if found:
            hits[cat] = found
    return hits


def _iocs(text):
    return {
        "urls": sorted({m.group(0).rstrip('\'",;)]}') for m in _URL.finditer(text)})[:32],
        "ips": sorted({m.group(0) for m in _IP.finditer(text)})[:32],
        "domains": sorted({m.group(0).lower() for m in _DOMAIN.finditer(text)})[:32],
    }


def triage_path(path, out_json=None, emu=False):
    """对单个样本/归档执行完整分诊，返回报告 dict。"""
    path = Path(path)
    report = {"file": str(path), "size": path.stat().st_size, "entries": [], "views": {}}
    workdir = TEMP / f"triage_{int(time.time()*1000)}"
    workdir.mkdir(exist_ok=True)

    blobs = []  # (显示名, Path)
    if path.suffix.lower() in (".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"):
        ok, err = _extract(path, workdir)
        report["extract"] = {"ok": ok, "error": err}
        if not ok:
            return report
        for f in sorted(workdir.rglob("*")):
            if f.is_file() and f.stat().st_size <= MAX_TOTAL:
                blobs.append((str(f.relative_to(workdir)), f))
    else:
        blobs.append((path.name, path))

    rules = sorted(str(p) for p in Path(__file__).resolve().parent.parent.glob("rules/*.yar"))

    from .signatures import load_db
    from .scanner import scan_file, ScanContext
    try:
        from .deobf import reveal
    except ImportError:
        reveal = None
    db = load_db()
    ctx = ScanContext(rules_paths=rules, deobf=True, emulate=bool(emu))

    for name, f in blobs[:MAX_FILES]:
        data = f.read_bytes()                     # 立即读内存（抗删）
        ent = {"name": name, "size": len(data),
               "md5": hashlib.md5(data).hexdigest(),
               "sha256": hashlib.sha256(data).hexdigest()}
        probe = workdir / f"__scan_{abs(hash(name)) % 99999}"
        probe.write_bytes(data)                   # 立即落盘立即扫
        try:
            ent["miniantivirus"] = [
                {"name": fd["name"], "level": fd["level"], "detail": fd["detail"][:160]}
                for fd in scan_file(probe, db, ctx)]
        finally:
            try:
                probe.unlink()
            except OSError:
                pass
        if reveal:
            try:
                rv = reveal(data)
                ent["deobf_layers"] = len(rv) if isinstance(rv, (list, tuple)) else 0
            except Exception:
                ent["deobf_layers"] = 0
        view_data = {}
        for tag, text in _decode_views(data[:MAX_TEXT]):
            if len(text.strip()) < 32:
                continue
            view_data[tag] = {"behavior": _behavior_hits(text), "iocs": _iocs(text)}
        ent["decode_tags"] = [t for t, v in view_data.items() if v["behavior"] or v["iocs"]["urls"] or v["iocs"]["domains"]] or (
            ["疑似行反转混淆（行为提取零命中，需人工还原分析）"] if "行反转还原" in view_data else [])
        ent["views"] = {t: v for t, v in view_data.items()
                        if v["behavior"] or v["iocs"]["urls"] or v["iocs"]["domains"]}
        report["entries"].append(ent)

    shutil.rmtree(workdir, ignore_errors=True)
    if out_json:
        Path(out_json).write_text(json.dumps(report, ensure_ascii=False, indent=1),
                                  encoding="utf-8")
    return report


def _print(report):
    print(f"=== 分诊: {Path(report['file']).name} ({report['size']}B) ===")
    if "extract" in report:
        print(f"[解包] {'成功' if report['extract']['ok'] else '失败: ' + report['extract']['error']}")
    for ent in report["entries"]:
        print(f"\n-- {ent['name']} ({ent['size']}B)")
        print(f"   md5={ent['md5']}  sha256={ent['sha256'][:32]}…")
        for fd in ent.get("miniantivirus", []):
            print(f"   [MiniAV/{fd['level'].upper()}] {fd['name']} — {fd['detail'][:80]}")
        if ent.get("deobf_layers"):
            print(f"   [deobf] 解混淆 {ent['deobf_layers']} 层")
        if ent.get("decode_tags"):
            print(f"   [解码] {'; '.join(ent['decode_tags'])}")
        for tag, v in ent.get("views", {}).items():
            print(f"   [视图:{tag}]")
            for cat, ks in v["behavior"].items():
                print(f"      {cat}: {', '.join(ks[:8])}")
            for k in ("urls", "domains", "ips"):
                if v["iocs"][k]:
                    print(f"      {k}: {', '.join(v['iocs'][k][:6])}")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        return 2
    src, out, emu = argv[0], None, False
    rest = argv[1:]
    while rest:
        a = rest.pop(0)
        if a == "--out":
            out = rest.pop(0)
        elif a == "--emu":
            emu = True
    rpt = triage_path(src, out_json=out, emu=emu)
    _print(rpt)
    if out:
        print(f"\n[i] JSON 报告: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
