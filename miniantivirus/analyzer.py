"""一键样本深度分析：任意文件 → 全面静态体检报告（绝不执行样本）。

聚合能力：
  基本信息（类型魔数 / 大小 / 熵 / md5-sha1-sha256）
  引擎检出（签名库哈希/模式/EICAR/YARA/压缩包/PE 启发式，复用 scanner）
  PE 深挖（编译时间戳 / 节区熵与 RWX / 可疑导入分类 / imphash / 嵌入签名）
  行为分析（脚本/宏文本特征链，复用 sandbox）
  IOC 提取（URL / IP / 注册表 / 文件路径）
  VirusTotal 信誉（可选）
  → 综合评分判定：清洁 / 可疑 / 恶意
"""

import hashlib
import re
import time
from pathlib import Path

from . import sandbox, scanner

_SCRIPT_SUFFIXES = {".ps1", ".psm1", ".bat", ".cmd", ".js", ".jse", ".vbs",
                    ".vba", ".py", ".php", ".sh", ".pl", ".rb"}

# 引擎检出级别 → 综合评分权重
_LEVEL_WEIGHT = {"high": 3, "medium": 1, "low": 0}

_IOC_RES = (
    # URL 字符白名单：不含引号/尖括号/反斜杠/非 ASCII，避免 UTF-16 乱码并入
    ("urls", re.compile(
        r"""https?://[A-Za-z0-9\-._~:/?#@!$&*+,;=%\[\]]{4,}""", re.I)),
    ("ips", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("regkeys", re.compile(
        r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
        r"HKEY_CLASSES_ROOT|HKEY_USERS)\\[^\s\"'<>]{2,}", re.I)),
    ("paths", re.compile(
        r"[A-Za-z]:\\[^\s\"'<>/:*?|]{2,}(?:\\[^\s\"'<>/:*?|]+)*")),
)
_IOC_CAP = 15
_IOC_BAD_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}
_IOC_LABELS = {"urls": "URL", "ips": "IP", "regkeys": "注册表", "paths": "路径"}


def detect_kind(path, data):
    """按魔数与后缀识别样本类型，返回 (kind, 描述)。

    kind ∈ pe / zip / pdf / office / script / text / binary。
    """
    if data[:2] == b"MZ":
        return "pe", "Windows PE 可执行文件"
    if data[:2] == b"PK":
        return "zip", "ZIP 压缩包"
    if data[:5] == b"%PDF-":
        return "pdf", "PDF 文档"
    if data[:8] == sandbox.OLE_MAGIC:
        return "office", "Office/OLE 复合文档"
    try:
        data[:4096].decode("utf-8")
        text_ok = True
    except UnicodeDecodeError:
        text_ok = False
    if text_ok:
        if path.suffix.lower() in _SCRIPT_SUFFIXES:
            return "script", "脚本文件"
        return "text", "文本文件"
    return "binary", "二进制数据文件"


def pe_info(path):
    """PE 结构深挖（需 pefile，缺失时优雅降级）。"""
    info = {"available": scanner.HAS_PEFILE}
    if not scanner.HAS_PEFILE:
        info["note"] = "未安装 pefile，跳过 PE 结构解析（pip install pefile 可启用）"
        return info
    try:
        pe = scanner.pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[
            scanner.pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            scanner.pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    except Exception as exc:
        info["note"] = f"PE 解析失败: {exc}"
        return info

    ts = int(pe.FILE_HEADER.TimeDateStamp or 0)
    info["compile_time"] = time.strftime(
        "%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if ts else "-"

    secs = []
    for s in pe.sections:
        chars = int(s.Characteristics)
        flags = "".join(ch for on, ch in (
            (chars & 0x40000000, "R"), (chars & 0x80000000, "W"),
            (chars & 0x20000000, "X")) if on)
        try:
            ent = round(float(s.get_entropy()), 2)
        except Exception:
            ent = None
        secs.append({"name": s.Name.rstrip(b"\x00").decode("ascii", "replace") or "-",
                     "entropy": ent, "flags": flags or "-"})
    info["sections"] = secs

    names = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            if imp.name:
                names.add(imp.name.decode("ascii", "ignore"))
    info["imports"] = len(names)
    info["suspicious"] = sorted(
        c for c, funcs in scanner.SUSPICIOUS_IMPORTS.items() if names & funcs)
    exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    info["exports"] = len(getattr(exports, "symbols", []) or [])
    try:
        info["imphash"] = pe.get_imphash() or ""
    except Exception:
        info["imphash"] = ""
    pe.close()

    try:
        from .wintrust import HAS_WINTRUST, verify_embedded
        if HAS_WINTRUST:
            cat, code = verify_embedded(str(path))
            info["sig"] = f"{cat} (0x{code & 0xFFFFFFFF:08X})" if code else cat
            info["sig_note"] = "仅校验嵌入签名（catalog 签名的系统文件会显示 unsigned）"
    except Exception:
        pass
    return info


def extract_iocs(data):
    """从原始字节提取 IOC（UTF-8 + UTF-16LE 双视图），每类去重并限量。"""
    text = data.decode("utf-8", "replace")
    try:
        text += "\n" + data.decode("utf-16-le", "ignore")
    except Exception:
        pass
    out = {}
    for key, rx in _IOC_RES:
        seen, vals = set(), []
        for m in rx.findall(text):
            v = m.strip().rstrip('.,;)"\'>') if key == "urls" else m.strip()
            if not v or v.lower() in seen:
                continue
            if key == "ips":
                parts = v.split(".")
                if v.lower() in _IOC_BAD_IPS or any(
                        not p.isdigit() or int(p) > 255 for p in parts):
                    continue
                # x.y.0.0 形态几乎都是 PE 版本号（如 5.1.0.0/10.0.0.0），排除
                if parts[2] == "0" and parts[3] == "0":
                    continue
            seen.add(v.lower())
            vals.append(v)
            if len(vals) >= _IOC_CAP:
                break
        out[key] = vals
    return out


def analyze_sample(path, db, ctx=None, vt=False):
    """对单个样本做全面静态分析，返回可 JSON 序列化的结果 dict。"""
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"path": str(path), "verdict": "错误", "score": 0,
                "score_src": [], "findings": [], "pe": None,
                "behavior": None, "iocs": {}, "vt": None, "vt_note": str(exc)}

    kind, desc = detect_kind(path, data)
    res = {
        "path": str(path), "kind": kind, "kind_desc": desc,
        "size": len(data),
        "hashes": {"md5": hashlib.md5(data).hexdigest(),
                   "sha1": hashlib.sha1(data).hexdigest(),
                   "sha256": hashlib.sha256(data).hexdigest()},
        "entropy": round(scanner.shannon_entropy(data[:4 * 1024 * 1024]), 2),
        "pe": None, "behavior": None, "vt": None, "vt_note": None,
    }

    if ctx is None:
        ctx = scanner.ScanContext()
    res["findings"] = scanner.scan_file(path, db, ctx)

    if kind == "pe":
        res["pe"] = pe_info(path)
    if kind in ("script", "office", "text"):
        res["behavior"] = sandbox.analyze(path)
    if kind != "zip":  # 压缩字节流里没有有意义的 IOC
        res["iocs"] = extract_iocs(data)
    else:
        res["iocs"] = {k: [] for k, _ in _IOC_RES}

    # ---- 已学习家族行为匹配（autolearn 行为库闭环：库内行为集 ⊆ 当前命中集）----
    observed = {h.get("name") for h in (res["behavior"] or {}).get("hits", [])
                if h.get("name") and h.get("name") != "SBX-Combo"}
    observed |= {fd.get("name") for fd in res["findings"]
                 if fd.get("name") and not fd.get("name").startswith("Auto_")
                 and fd.get("name") != "Learned-Behavior-Family"}
    for fam, meta in sandbox.match_families(db, observed):
        res["findings"].append({
            "name": "Learned-Behavior-Family",
            "level": "high" if meta.get("category") == "Ransomware" else "medium",
            "detail": (f"行为特征命中已学习家族 [{fam}]（{meta.get('category')}"
                       f"，库内 {len(meta.get('behaviors') or [])} 项行为）")})

    if vt:
        from .vt import VTClient
        if not VTClient.has_key():
            res["vt_note"] = "未配置 VT_API_KEY，跳过信誉查询"
        else:
            try:
                res["vt"] = VTClient.shared().query(res["hashes"]["sha256"])
            except RuntimeError as exc:
                res["vt_note"] = str(exc)

    # ---- 综合评分 ----
    score, src = 0, []
    for fd in res["findings"]:
        w = _LEVEL_WEIGHT.get(fd.get("level"), 0)
        if w:
            score += w
            src.append(f"{fd['name']}({fd['level']})")
    if res["behavior"]:
        bv, bs = res["behavior"]["verdict"], res["behavior"]["score"]
        if bv == "恶意":
            score += 3
            src.append(f"行为=恶意({bs})")
        elif bv == "可疑":
            score += 1
            src.append(f"行为=可疑({bs})")
    if res["vt"]:
        mal = int(res["vt"].get("malicious", 0))
        sus = int(res["vt"].get("suspicious", 0))
        if mal:
            score += 3 if mal >= 3 else 2
            src.append(f"VT malicious={mal}")
        elif sus:
            score += 1
            src.append(f"VT suspicious={sus}")
    res["score"], res["score_src"] = score, src
    res["verdict"] = "恶意" if score >= 4 else ("可疑" if score >= 1 else "清洁")
    return res


def format_report(r):
    """渲染终端文本报告。"""
    L = [f"样本深度分析: {r['path']}",
         f"类型: {r['kind_desc']} · 大小 {r['size']:,} 字节 · 熵 {r['entropy']}/8",
         f"md5 : {r['hashes']['md5']}",
         f"sha1: {r['hashes']['sha1']}",
         f"sha256: {r['hashes']['sha256']}"]
    if r["verdict"] == "错误":
        L.append(f"判定: 错误 — {r.get('vt_note') or '无法读取'}")
        return "\n".join(L)

    extra = " · ".join(r.get("score_src", []))
    L.append(f"判定: {r['verdict']}（综合评分 {r['score']}）"
             + (f"  来源: {extra}" if extra else ""))

    fds = [fd for fd in r.get("findings", []) if fd.get("level") in _LEVEL_WEIGHT]
    if fds:
        L.append(f"── 引擎检出 {len(fds)} 条 ──")
        for fd in fds:
            L.append(f"  [{fd['level'].upper()}] {fd['name']} — {fd['detail']}")

    pe = r.get("pe")
    if pe:
        if pe.get("available"):
            L.append("── PE 结构 ──")
            L.append(f"  编译时间: {pe.get('compile_time', '-')} · "
                     f"imphash: {pe.get('imphash') or '-'} · "
                     f"导入 {pe.get('imports', 0)} · 导出 {pe.get('exports', 0)}")
            if pe.get("sections"):
                L.append("  节区: " + ", ".join(
                    f"{s['name']}(熵 {s['entropy']},{s['flags']})"
                    for s in pe["sections"]))
            if pe.get("suspicious"):
                L.append("  可疑导入分类: " + ", ".join(pe["suspicious"]))
            if pe.get("sig"):
                L.append(f"  数字签名(嵌入): {pe['sig']}")
                if pe.get("sig_note"):
                    L.append(f"  ({pe['sig_note']})")
        elif pe.get("note"):
            L.append(f"(i) {pe['note']}")

    b = r.get("behavior")
    if b:
        L.append("── 行为分析 ──")
        for ln in sandbox.format_report(b).splitlines()[1:]:
            L.append("  " + ln.lstrip())

    iocs = r.get("iocs") or {}
    total = sum(len(v) for v in iocs.values())
    if total:
        L.append(f"── IOC 提取 {total} 条 ──")
        for key in ("urls", "ips", "regkeys", "paths"):
            vals = iocs.get(key) or []
            if vals:
                head = "; ".join(vals[:8]) + ("…" if len(vals) > 8 else "")
                L.append(f"  {_IOC_LABELS[key]}({len(vals)}): {head}")

    if r.get("vt_note"):
        L.append(f"(i) VT: {r['vt_note']}")
    if r.get("vt"):
        vt = r["vt"]
        L.append(f"── VT 信誉 ──  malicious={vt.get('malicious', 0)} "
                 f"suspicious={vt.get('suspicious', 0)} "
                 f"harmless={vt.get('harmless', 0)}")

    if r["verdict"] == "清洁" and not fds:
        L.append("  未发现可疑特征")
    return "\n".join(L)
