"""核心扫描逻辑：哈希 / 模式签名 / EICAR / YARA / PE 启发式 / 压缩包 / VT 信誉 + 隔离区。"""

import hashlib
import json
import math
import re
import shutil
import sys
import time
from pathlib import Path

from .signatures import MAX_CONTENT_SCAN, QUAR_DIR, is_excluded

_EICAR = "".join(["X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-", "STANDARD-",
                  "ANTIVIRUS-", "TEST-FILE!$H+H*"])

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

SUSPICIOUS_IMPORTS = {
    "alloc": {"VirtualAlloc", "VirtualAllocEx", "NtAllocateVirtualMemory"},
    "write": {"WriteProcessMemory", "NtWriteVirtualMemory"},
    "exec": {"CreateRemoteThread", "NtCreateThreadEx", "SetThreadContext", "QueueUserAPC"},
    "hook": {"SetWindowsHookExA", "SetWindowsHookExW"},
    "download": {"URLDownloadToFileA", "URLDownloadToFileW"},
}

_ANALYSIS_ARTIFACTS = (b"sbiedll.dll", b"vboxservice.exe", b"vboxtray.exe", b"vmtoolsd.exe",
                       b"vmwareuser.exe", b"qemu-ga", b"cuckoo", b"ollydbg", b"x64dbg",
                       b"cheatengine", b"wireshark", b"fiddler")

# 巨型 hex 常量（≥32K 字符的连续 [0-9a-fA-F] 串）——hex 编码载荷释放器标志
_HEX_RUN = re.compile(rb"[0-9a-fA-F]{32768,}")

_RULES_CACHE = {}

CACHE_FILE = Path(__file__).resolve().parent.parent / "scan_cache.json"
_CACHE = {"fp": None, "files": {}, "dirty": False}
_CACHE_STATS = {"hits": 0}


def cache_fingerprint(db, rules_paths=None):
    """缓存指纹：签名库哈希/模式 + 规则文件的 size/mtime。"""
    payload = json.dumps({"h": db.get("hashes"), "p": db.get("patterns")}, sort_keys=True)
    fp = hashlib.sha256(payload.encode("utf-8", "ignore")).hexdigest()[:16]
    for rp in sorted(rules_paths or []):
        try:
            st = Path(rp).stat()
            fp += hashlib.sha256(f"{rp}:{st.st_size}:{st.st_mtime_ns}".encode()).hexdigest()[:16]
        except OSError:
            continue
    return fp


def _cache_load(fp):
    _CACHE["fp"] = fp
    _CACHE["files"] = {}
    _CACHE["dirty"] = False
    try:
        obj = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        if obj.get("fp") == fp:
            files = obj.get("files", {})
            if isinstance(files, dict):
                _CACHE["files"] = files
    except (OSError, ValueError):
        pass


def _cache_get(path, fp):
    if _CACHE["fp"] != fp:
        _cache_load(fp)
    ent = _CACHE["files"].get(str(path))
    if not ent:
        return False
    try:
        st = path.stat()
    except OSError:
        return False
    if ent[0] == st.st_size and ent[1] == st.st_mtime_ns:
        _CACHE_STATS["hits"] += 1
        return True
    return False


def _cache_put(path):
    try:
        st = Path(path).stat()
    except OSError:
        return
    _CACHE["files"][str(path)] = [st.st_size, st.st_mtime_ns]
    _CACHE["dirty"] = True
    if len(_CACHE["files"]) > 60000:
        _CACHE["files"] = dict(list(_CACHE["files"].items())[30000:])


def flush_cache():
    """把本次扫描产生的清洁缓存写回磁盘（原子替换）。"""
    if not _CACHE.get("dirty") or _CACHE.get("fp") is None:
        return
    try:
        tmp = CACHE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"fp": _CACHE["fp"], "files": _CACHE["files"]}),
                       encoding="utf-8")
        tmp.replace(CACHE_FILE)
    except OSError:
        return
    _CACHE["dirty"] = False


def reset_cache():
    """清空缓存（测试/手动重置用）。"""
    _CACHE.update({"fp": None, "files": {}, "dirty": False})
    _CACHE_STATS["hits"] = 0
    try:
        CACHE_FILE.unlink()
    except OSError:
        pass


def cache_hits():
    return _CACHE_STATS["hits"]


class ScanContext:
    """一次扫描会话的上下文：YARA 规则、排除项、白名单、VT 开关。

    rules 采用"路径 + 惰性编译"设计：YARA Rules 对象不可跨进程
    pickle，多进程扫描时每个子进程按路径自行编译（见 _RULES_CACHE）。
    fast=True 时启用增量缓存：未变更的清洁文件直接跳过（结果为空）。
    """

    def __init__(self, rules_paths=None, excludes=None, whitelist=None,
                 vt=False, sigcheck=False, fast=False,
                 deobf=True, emulate=False):
        self.rules_paths = [str(p) for p in (rules_paths or [])]
        self.excludes = [str(e) for e in (excludes or [])]
        self.whitelist = dict(whitelist or {})
        self.vt = bool(vt)
        self.sigcheck = bool(sigcheck)
        self.fast = bool(fast)
        self.deobf = bool(deobf)
        self.emulate = bool(emulate)
        self.cache_fp = None
        self._rules = None
        self._compiled = False

    def to_spec(self):
        return {"rules_paths": self.rules_paths,
                "excludes": self.excludes,
                "whitelist": self.whitelist,
                "vt": self.vt,
                "sigcheck": self.sigcheck,
                "fast": self.fast,
                "deobf": self.deobf,
                "emulate": self.emulate}

    @classmethod
    def from_spec(cls, spec):
        return cls(rules_paths=spec.get("rules_paths"),
                   excludes=spec.get("excludes"),
                   whitelist=spec.get("whitelist"),
                   vt=bool(spec.get("vt")),
                   sigcheck=bool(spec.get("sigcheck")),
                   fast=bool(spec.get("fast")),
                   deobf=bool(spec.get("deobf", True)),
                   emulate=bool(spec.get("emulate", False)))

    def get_rules(self):
        if self._compiled:
            return self._rules
        self._compiled = True
        if self.rules_paths and HAS_YARA:
            key = tuple(self.rules_paths)
            compiled = _RULES_CACHE.get(key)
            if compiled is None:
                try:
                    compiled = yara.compile(filepaths={
                        str(i): p for i, p in enumerate(self.rules_paths)})
                except yara.Error as exc:
                    print(f"[!] YARA 规则编译失败，本次忽略规则: {exc}")
                    compiled = False
                _RULES_CACHE[key] = compiled
            self._rules = compiled or None
        return self._rules


def file_hashes(path):
    md5, sha = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1048576), b""):
            md5.update(chunk)
            sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()


def hash_all(path):
    """一次读取计算 md5/sha1/sha256，返回 {算法: 摘要}。"""
    ctxs = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1048576), b""):
            for h in ctxs.values():
                h.update(chunk)
    return {algo: h.hexdigest() for algo, h in ctxs.items()}


def shannon_entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in freq if c)


def pe_heuristics(data):
    """对 PE 文件做启发式分析，返回 finding dict 或 None。"""
    reasons, score = [], 0
    sample = data[:4194304]
    ent = shannon_entropy(sample)
    if ent > 7.4:
        reasons.append(f"文件熵偏高 {ent:.2f}/8（疑似加壳/加密）")
        score += 1
    if not HAS_PEFILE:
        if reasons:
            return {"name": "PE-Heuristic-Suspect",
                    "level": "medium",
                    "detail": "; ".join(reasons) + "（pip install pefile 可启用导入表分析）"}
        return None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        return None
    imported = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            if not imp.name:
                continue
            imported.add(imp.name.decode("ascii", "ignore"))
    cats = [c for c, funcs in SUSPICIOUS_IMPORTS.items() if imported & funcs]
    if {"alloc", "write", "exec"} <= set(cats):
        reasons.append("导入表含完整进程注入 API 组合（分配/写入/远程执行）")
        score += 2
    elif len(cats) >= 2:
        reasons.append("导入表含可疑 API 组合: " + ", ".join(sorted(cats)))
        score += 1
    elif cats == ["download"]:
        reasons.append("导入表含 URLDownloadToFile")
        score += 1
    rwx, max_ent = [], 0.0
    for s in pe.sections:
        chars = int(s.Characteristics)
        if chars & 0x80000000 and chars & 0x20000000:
            rwx.append(s.Name.rstrip(b"\x00").decode("ascii", "replace") or "-")
        try:
            max_ent = max(max_ent, float(s.get_entropy()))
        except Exception:
            continue
    if rwx:
        reasons.append("存在可写可执行节区（RWX，自解密/免杀 Loader 常见）: "
                       + ", ".join(rwx[:4]))
        score += 1
    if max_ent > 7.8 and 0 < len(imported) <= 10:
        reasons.append(f"节区熵极高({max_ent:.2f})且导入 API 极少({len(imported)})，"
                       "疑似加密载荷 Loader")
        score += 1
    stubs = data[:2097152].count(b"\x0f\x05\xc3")
    if stubs >= 6 and (rwx or {"alloc", "write", "exec"} <= set(cats)):
        reasons.append(f"检出 {stubs} 处 syscall;ret 桩（直接系统调用特征）")
        score += 1
    blob = data[:2097152].lower()
    try:
        wide = data[:1048576].decode("utf-16-le", "ignore").lower().encode("utf-8", "ignore")
    except Exception:
        wide = b""
    arts = sum(1 for a in _ANALYSIS_ARTIFACTS if a in blob or a in wide)
    if arts >= 3:
        reasons.append(f"内嵌 {arts} 个分析环境痕迹字符串（反沙箱探测）")
        score += 1
    # 免杀 Loader 专用沙箱 drop 探针（C:\Users\Public\1234567.txt，高置信 IOC）
    if b"1234567.txt" in blob or b"1234567.txt" in wide:
        reasons.append("内嵌反沙箱 drop 探针路径（users\\public\\1234567.txt，"
                       "免杀 Loader 沙箱识别标记）")
        score += 1
    # 对称加密原语常量（AES S-box / TEA-XTEA delta / SM4 FK）+ 内存执行能力：
    # 单独出现无意义（OpenSSL 等正常程序含 AES 常量），组合才有载荷解包语义
    crypto_marks = []
    if b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5" in data[:2097152]:
        crypto_marks.append("AES S-box")
    if b"\xb9\x79\x37\x9e" in data[:2097152]:
        crypto_marks.append("TEA/XTEA delta")
    if b"\xc6\xba\xb1\xa3" in data[:2097152]:
        crypto_marks.append("SM4 FK")
    if crypto_marks and (rwx or {"alloc", "write", "exec"} <= set(cats)):
        reasons.append("内置对称加密常量(" + ", ".join(crypto_marks) + ") 且具备内存执行能力"
                       "（多层加密 Shellcode 解包典型组合）")
        score += 1
    # 仿冒可信厂商：版本资源声称 Microsoft 且节区高熵（签名伪造/伪装常见）
    if b"microsoft corporation" in blob and max_ent > 7.5:
        reasons.append("声称 Microsoft Corporation 且节区高熵 "
                       f"({max_ent:.2f}/8，疑似仿冒可信厂商属性)")
        score += 1
    if not reasons:
        return None
    return {"name": "PE-Heuristic-Suspect",
            "level": "high" if score >= 2 else "medium",
            "detail": "; ".join(reasons)}


def signature_finding(cat, code, is_driver=False):
    """把签名校验结果 (cat, code) 转换为检出条目；无可报时返回 None。

    fail 细分：0x800B0109 (CERT_E_UNTRUSTEDROOT) 单列——签名结构存在但
    证书链不受信，是自签名/伪造签名伪装可信程序的典型静态特征。
    """
    if cat == "fail":
        if code == 0x800B0109:
            return {"name": "Untrusted-Signature-Root", "level": "high",
                    "detail": "签名存在但证书链不受信 (0x800B0109)，"
                              "常见于自签名/伪造签名伪装可信程序"}
        return {"name": "Authenticode-Fail", "level": "high",
                "detail": f"数字签名校验失败 (0x{code:08X})，"
                          "文件可能被篡改或签名者不受信"}
    if cat == "unsigned":
        if is_driver:
            return {"name": "Unsigned-Driver", "level": "high",
                    "detail": "内核驱动无数字签名，可被任意加载，"
                              "属 BYOVD 攻击典型前提"}
        return {"name": "Unsigned-PE", "level": "low",
                "detail": "PE 文件无 Authenticode 数字签名"}
    return None


def _weight_level(weight):
    return "high" if weight >= 3 else ("medium" if weight >= 2 else "low")


def deobf_findings(data, db, ctx):
    """迭代解混淆后对还原载荷复扫（反制变量名/字符串层混淆）。

    还原层命中以原规则名报告，detail 标注解混淆链路；层数≥2 的隐藏
    内容即使无规则命中也报 low（编码套编码本身即是规避信号）。
    """
    from . import deobf as _deobf
    from . import sandbox as _sandbox
    out, max_depth, seen = [], 0, set()
    for chain, blob in _deobf.reveal(data):
        max_depth = max(max_depth, chain.count("→") + 1)
        for fd in content_findings(blob, db, ctx):
            if fd.get("level") == "error":
                continue
            key = (fd["name"], fd.get("detail", ""))
            if key in seen:
                continue
            seen.add(key)
            out.append({**fd, "detail": f"解混淆({chain})后命中: {fd.get('detail', '')}"})
        try:
            text = blob.decode("utf-8", "replace")
        except Exception:
            continue
        for h in _sandbox.text_hits(text):
            key = (h["name"], h["sample"])
            if key in seen:
                continue
            seen.add(key)
            out.append({"name": h["name"], "level": _weight_level(h["weight"]),
                        "detail": f"解混淆({chain})后命中行为特征: {h['desc']}"})
    if not out and max_depth >= 2:
        out.append({"name": "Obfuscated-Content", "level": "low",
                    "detail": f"检测到 {max_depth} 层嵌套编码载荷（base64/压缩/转义套叠），"
                              "内容隐藏但未命中已知特征"})
    return out


def emu_findings(data, db, ctx):
    """Unicorn 受限模拟后对运行时内存复扫（反制控制流混淆）。"""
    from . import emu as _emu
    from . import sandbox as _sandbox
    out, seen = [], set()
    for desc, frag in _emu.emulate(data):
        for fd in content_findings(frag, db, ctx):
            if fd.get("level") == "error":
                continue
            key = (fd["name"], fd.get("detail", ""))
            if key in seen:
                continue
            seen.add(key)
            out.append({**fd, "detail": f"Unicorn 模拟内存({desc})还原后命中: "
                                        f"{fd.get('detail', '')}"})
        try:
            text = frag.decode("utf-8", "replace")
        except Exception:
            continue
        for h in _sandbox.text_hits(text):
            key = (h["name"], h["sample"])
            if key in seen:
                continue
            seen.add(key)
            out.append({"name": h["name"], "level": _weight_level(h["weight"]),
                        "detail": f"Unicorn 模拟内存({desc})还原行为特征: {h['desc']}"})
    return out


def hex_blob_findings(data):
    """巨型十六进制常量检测（银狐 core 手法：脚本常量内嵌 hex 编码的
    PE 载荷，运行时 bytes.fromhex 落地执行；对源码/pyc/还原 blob 场景
    通用）。仅报存在性，需人工研判。"""
    window = data[:16 * 1024 * 1024]
    if len(data) > 20 * 1024 * 1024:
        window += data[-4 * 1024 * 1024:]
    for m in _HEX_RUN.finditer(window):
        blob = m.group(0)
        if len(set(blob[:256])) < 8:      # 单一/极窄字符填充（如哈希表占位）不算
            continue
        size = len(blob)
        size_txt = (f"{size / 1048576:.1f} MB" if size >= 1048576
                    else f"{size // 1024} KB")
        return [{"name": "Hex-Blob-Dropper",
                 "level": "high" if size >= 1048576 else "medium",
                 "detail": f"检测到 {size_txt} 超长十六进制常量串"
                           "（hex 编码载荷释放器典型手法，需人工研判）"}]
    return []


def content_findings(data, db, ctx=None):
    """对一段字节内容做模式/EICAR/YARA 检测（供文件与压缩包条目复用）。"""
    findings = []
    text = None
    for sig in db.get("patterns", []):
        stype = sig.get("type")
        try:
            if stype == "hex":
                if bytes.fromhex(sig["data"]) in data:
                    findings.append({"name": sig["name"],
                                     "level": sig.get("level", "medium"),
                                     "detail": "字节模式匹配"})
            elif stype == "regex":
                if text is None:
                    text = data.decode("utf-8", "replace")
                if sig.get("data") and re.search(sig["data"], text):
                    findings.append({"name": sig["name"],
                                     "level": sig.get("level", "medium"),
                                     "detail": "正则模式匹配"})
        except (ValueError, re.error):
            continue
    if _EICAR.encode() in data:
        findings.append({"name": "EICAR-Test-File", "level": "high",
                         "detail": "EICAR 标准杀软测试文件特征"})
    rules = ctx.get_rules() if ctx else None
    if rules is not None:
        try:
            matches = rules.match(data=data)
        except yara.Error:
            matches = []
        for m in matches:
            level = "medium"
            meta = getattr(m, "meta", None) or {}
            lv = str(meta.get("level", "")).lower()
            if lv in ("high", "medium", "low"):
                level = lv
            findings.append({"name": m.rule, "level": level,
                             "detail": "YARA 规则匹配"})
    return findings


def scan_file(path, db, ctx=None):
    """返回该文件的检出列表 [{name, level, detail}]。"""
    path = Path(path)
    ctx = ctx or ScanContext()
    if ctx.excludes and is_excluded(path, ctx.excludes):
        return []
    if ctx.fast:
        if ctx.cache_fp is None:
            ctx.cache_fp = cache_fingerprint(db, ctx.rules_paths)
        if _cache_get(path, ctx.cache_fp):
            return []
    try:
        _md5, sha = file_hashes(path)
    except OSError as exc:
        return [{"name": f"无法读取: {exc}", "level": "error"}]
    if sha in ctx.whitelist:
        return []
    findings = []
    hit = db.get("hashes", {}).get("sha256", {}).get(sha)
    if hit:
        findings.append({"name": hit.get("name", "Unknown"),
                         "level": hit.get("level", "high"),
                         "detail": "sha256 哈希精确匹配"})
    else:
        try:
            hashes = hash_all(path)
        except OSError:
            hashes = {}
        for algo in ("md5", "sha1"):
            hit = db.get("hashes", {}).get(algo, {}).get(hashes.get(algo, ""))
            if not hit:
                continue
            findings.append({"name": hit.get("name", "Unknown"),
                             "level": hit.get("level", "high"),
                             "detail": f"{algo} 哈希精确匹配"})
            break
    vuln = db.get("vulnerable_drivers", {})
    if sha in vuln:
        info = vuln[sha]
        name = info.get("name") if isinstance(info, dict) else str(info)
        findings.append({"name": name or "Vulnerable-Driver",
                         "level": "high",
                         "detail": "命中漏洞/恶意驱动黑名单（BYOVD 滥用风险）"})
    try:
        st_size = path.stat().st_size
        if st_size <= MAX_CONTENT_SCAN:
            data = path.read_bytes()
        else:
            # 大文件头尾分段读：头 64MB（PE 头/嵌入载荷/内嵌串）+
            # 尾 8MB（PyInstaller/NSIS/Inno 的 TOC 与目录型 IOC 集中在尾部）
            with open(path, "rb") as fh:
                data = fh.read(MAX_CONTENT_SCAN)
                fh.seek(-8 * 1024 * 1024, 2)
                data += fh.read(8 * 1024 * 1024)
    except OSError:
        return findings
    findings += content_findings(data, db, ctx)
    try:
        from .pyinst import pyinst_findings
        findings += pyinst_findings(data)
    except Exception as exc:
        findings.append({"name": "PyInst-Error", "level": "low",
                         "detail": f"PyInstaller 结构解析异常（已跳过）: {exc}"})
    if ctx.deobf and not findings:
        try:
            findings += deobf_findings(data, db, ctx)
        except Exception as exc:
            findings.append({"name": "Deobf-Error", "level": "low",
                             "detail": f"解混淆引擎异常（已跳过）: {exc}"})
        if not findings:
            findings += hex_blob_findings(data)
    if data[:2] == b"PK":
        from .archive import scan_zip
        try:
            findings += scan_zip(path, db, ctx)
        except Exception as exc:
            findings.append({"name": "ZIP-Error", "level": "low",
                             "detail": f"压缩包解析失败: {exc}"})
    if data[:2] == b"MZ":
        is_driver = path.suffix.lower() == ".sys"
        if not is_driver and HAS_PEFILE:
            try:
                _pe = pefile.PE(data=data, fast_load=True)
                is_driver = int(_pe.OPTIONAL_HEADER.Subsystem) == 1
            except Exception:
                pass
        heur = pe_heuristics(data)
        if heur:
            findings.append(heur)
        if ctx.emulate and len(data) <= 8 * 1024 * 1024:
            try:
                findings += emu_findings(data, db, ctx)
            except Exception as exc:
                findings.append({"name": "Emu-Error", "level": "low",
                                 "detail": f"模拟引擎异常（已跳过）: {exc}"})
        if ctx.sigcheck:
            try:
                if is_driver:
                    from .wintrust import verify_driver
                    cat, code = verify_driver(str(path))
                else:
                    from .wintrust import verify
                    cat, code = verify(str(path))
            except Exception:
                cat, code = None, None
            if cat in ("fail", "unsigned"):
                fd_sig = signature_finding(cat, code, is_driver)
                if fd_sig:
                    findings.append(fd_sig)
        if ctx.vt:
            from .vt import VTClient, finding_from_stats
            if VTClient.has_key():
                try:
                    fd = finding_from_stats(VTClient.shared().query(sha))
                except RuntimeError as exc:
                    print(f"[!] VT 查询失败: {exc}")
                    fd = None
                if fd:
                    findings.append(fd)
    if ctx.fast and not findings:
        _cache_put(path)
    return findings


def quarantine_file(path, finding):
    QUAR_DIR.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    qname = f"{ts}-{path.name}.quar"
    _md5, sha = file_hashes(path)
    meta = {"name": qname,
            "original": str(path.resolve()),
            "finding": finding.get("name", "unknown"),
            "time": ts,
            "sha256": sha}
    shutil.move(str(path), str(QUAR_DIR / qname))
    (QUAR_DIR / (qname + ".meta.json")).write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return qname


def quarantine_restore(qname):
    meta_path = QUAR_DIR / f"{qname}.meta.json"
    if not meta_path.exists():
        sys.exit(f"隔离记录不存在: {qname}")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    src = QUAR_DIR / qname
    if not src.exists():
        sys.exit(f"隔离文件丢失: {src}")
    original = Path(meta["original"])
    original.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(original))
    meta_path.unlink()
    return str(original)


def _in_quarantine(p):
    return QUAR_DIR == p or QUAR_DIR in p.parents
