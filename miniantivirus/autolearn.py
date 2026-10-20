"""样本自动学习：分析判定恶意后自动把特征入库（哈希 + 自动 YARA 规则）。

学习条件（全部满足才入库，防误报污染签名库）：
  综合判定 == 恶意（analyze_sample 评分 >= 4）
  样本 sha256 不在白名单
  未学习过同一样本（sha256 查重）

入库内容：
  md5/sha1/sha256 三算法哈希（level=high，名称取最高危检出项名）
  自动 YARA 规则（附加到 rules/auto_learned.yar）：
    PE 样本加 MZ 门，脚本/文本用 filesize 门，字符串 >= 2 条 + 组合计数
    条件（至少 2 of），meta.auto_generated=true 便于审查与批量清理。
    自动规则写入前先试编译，失败自动回滚，只保留哈希。
  行为特征（db["behaviors"]，按家族聚合）：泛化行为名并集（SBX-* / 家族级 YARA
    规则名等，剔除样本专属 Auto_ 规则），供 Learned-Behavior-Family 家族匹配，
    category 为 Ransomware（命中勒索特征）或 Malware。

绝不执行样本：仅静态读取字节做字符串/IOC 提取。
"""

import re
import time
from pathlib import Path

from . import scanner
from .signatures import RULES_DIR

AUTO_YAR = "auto_learned.yar"

# 自动生成规则的字符串噪音过滤（运行时/编译器/PE 结构常见串）
_NOISE_RE = re.compile(
    r"""(?xi)(
        ^\d+$ |                     # 纯数字
        kernel32|user32|gdi32|shell32|advapi32|ntdll|msvcrt|ucrtbase|
        ole32|oleaut32|comctl32|comdlg32|shlwapi|wininet|ws2_32|mscoree|
        kernelbase|vcruntime|api-ms-|ext-ms-|
        \.(dll|exe|sys|ocx|cpl)$ |  # 以模块后缀结尾的裸名
        this\ program\ cannot|      # DOS stub
        ^\.?[a-z]{2,4}$ |           # 太短的节名/单词
        [<>:"'|?*\x00]              # 含难转义字符
    )""")

_STR_RE = re.compile(r"[\x20-\x7e]{8,64}")
_SCAN_BYTES = 2 * 1024 * 1024   # 字符串提取只看前 2MB


def _escape(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _family(result):
    """最高危检出项名的安全形态（哈希签名入库用）。"""
    for fd in sorted(result.get("findings", []),
                     key=lambda f: f.get("level") == "high",
                     reverse=True):
        if fd.get("name") == "Learned-Behavior-Family":
            continue
        if fd.get("level") in ("high", "medium"):
            fam = re.sub(r"[^A-Za-z0-9_]", "_", str(fd.get("name", "")))[:40]
            if fam:
                return fam
    return "Sample"


def _observed_behaviors(result):
    """泛化行为名集合（行为层命中 + 引擎检出），剔除样本专属规则名。

    SBX-Combo 可由底层规则推导、Auto_* 为单样本哈希/字符串规则、
    Learned-Behavior-Family 是匹配结果自身，均不入库（防反馈污染）。
    """
    names = set()
    for h in (result.get("behavior") or {}).get("hits", []):
        n = str(h.get("name") or "")
        if n and n != "SBX-Combo":
            names.add(n)
    for fd in result.get("findings", []):
        n = str(fd.get("name") or "")
        if n and not n.startswith("Auto_") and n != "Learned-Behavior-Family":
            names.add(n)
    return names


def _category(result):
    """家族类别：命中勒索相关特征 → Ransomware，否则 Malware。"""
    blob = " ".join(
        [f"{h.get('name', '')} {h.get('desc', '')}"
         for h in (result.get("behavior") or {}).get("hits", [])]
        + [f"{fd.get('name', '')} {fd.get('detail', '')}"
           for fd in result.get("findings", [])]).lower()
    return "Ransomware" if "ransom" in blob else "Malware"


def _rule_name(result, sha256):
    """规则名：Auto_ + 家族名 + 摘要前 8 位（保证唯一）。"""
    return f"Auto_{_family(result)}_{sha256[:8]}"


def _candidate_strings(result, data, cap=6):
    """候选特征串：IOC 里的 URL 优先（高置信），再补独特可打印串。"""
    out, seen = [], set()

    def push(s):
        s = s.strip()
        if 8 <= len(s) <= 64 and s.lower() not in seen and not _NOISE_RE.search(s):
            seen.add(s.lower())
            out.append(s)

    for u in (result.get("iocs") or {}).get("urls", [])[:2]:
        push(u)
    for m in _STR_RE.findall(data[:_SCAN_BYTES].decode("latin-1", "replace")):
        if len(out) >= cap:
            break
        push(m)
    return out


def _build_rule(result, data):
    """生成 YARA 规则文本；候选串不足 2 条时返回 None（太弱，宁可不加）。"""
    strs = _candidate_strings(result, data)
    if len(strs) < 2:
        return None, strs
    sha = result["hashes"]["sha256"]
    name = _rule_name(result, sha)
    kind = result.get("kind")
    if kind == "pe":
        gate = "uint16(0) == 0x5A4D and "
    elif kind in ("script", "text"):
        gate = "filesize < 4MB and "
    else:   # zip/office/pdf/binary：无可靠结构门，不生成规则
        return None, strs
    lines = [f"rule {name}", "{", "    meta:",
             '        auto_generated = "true"',
             f'        source_sha256 = "{sha}"',
             f'        learned = "{time.strftime("%Y-%m-%d")}"',
             "    strings:"]
    for i, s in enumerate(strs, 1):
        lines.append(f'        $s{i} = "{_escape(s)}" ascii')
    lines += ["    condition:", f"        {gate}2 of ($s*)", "}"]
    return "\n".join(lines) + "\n", strs


def _append_rule(rules_dir, rule_text, rule_name):
    """追加规则到 auto_learned.yar；返回 (是否写入, 消息)。"""
    rules_dir = Path(rules_dir)
    rules_dir.mkdir(parents=True, exist_ok=True)
    yar = rules_dir / AUTO_YAR
    old = yar.read_text(encoding="utf-8") if yar.exists() else ""
    if re.search(rf"\brule\s+{re.escape(rule_name)}\b", old):
        return False, "规则已存在"
    yar.write_text(old.rstrip("\n") + "\n\n" + rule_text
                   if old.strip() else rule_text, encoding="utf-8")
    # 试编译，失败回滚到追加前的内容
    if scanner.HAS_YARA:
        try:
            import yara
            yara.compile(filepath=str(yar))
        except Exception as exc:
            yar.write_text(old, encoding="utf-8")
            return False, f"规则编译失败已回滚: {str(exc).splitlines()[0][:80]}"
    return True, "已生成"


def learn_from_result(result, db, rules_dir=None):
    """从 analyze_sample 结果学习特征入库（只改传入 db，落盘由调用方 save_db）。

    返回摘要 dict：{"learned": bool, "hashes": [algo...], "rule": str|None,
                    "strings": int, "behaviors": [name...], "category": str|None,
                    "notes": [str...]}
    """
    notes = []
    if result.get("verdict") != "恶意":
        return {"learned": False, "hashes": [], "rule": None,
                "strings": 0, "behaviors": [], "category": None,
                "notes": [f"判定为 {result.get('verdict')}，不学习"]}
    sha = result["hashes"]["sha256"]
    if sha in db.get("whitelist", {}):
        return {"learned": False, "hashes": [], "rule": None,
                "strings": 0, "behaviors": [], "category": None,
                "notes": ["样本在白名单中，不学习"]}

    from .sigdb import add_hash
    name = _family(result)
    added = []
    for algo in ("md5", "sha1", "sha256"):
        _a, _d, is_new = add_hash(db, result["hashes"][algo], name, "high",
                                  algo=algo)
        if is_new:
            added.append(algo)
    if not added:
        notes.append("哈希已存在，跳过")

    # ---- 行为特征入库（家族级泛化行为集，供 Learned-Behavior-Family 匹配）----
    cat, behs_n = None, 0
    behaviors = _observed_behaviors(result)
    if behaviors:
        fam_key = _family(result)
        bdb = db.setdefault("behaviors", {})
        ent = bdb.get(fam_key)
        if ent is None:
            cat = _category(result)
            bdb[fam_key] = {"category": cat,
                            "behaviors": sorted(behaviors)[:64],
                            "score": int(result.get("score") or 0),
                            "first_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "samples": [sha]}
            behs_n = len(bdb[fam_key]["behaviors"])
            notes.append(f"行为特征入库: {fam_key}（{cat}，{behs_n} 项行为）")
        else:
            merged = sorted(set(ent.get("behaviors") or []) | behaviors)[:64]
            ent["behaviors"] = merged
            old_cat = ent.get("category") or "Malware"
            new_cat = _category(result)
            # 勒索类别一旦确立不降级
            ent["category"] = ("Ransomware" if "Ransomware" in (old_cat, new_cat)
                               else "Malware")
            cat = ent["category"]
            ent["score"] = max(int(ent.get("score") or 0),
                               int(result.get("score") or 0))
            samples = ent.setdefault("samples", [])
            if sha not in samples:
                samples.append(sha)
                del samples[:-16]
            ent["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")
            behs_n = len(merged)
            notes.append(f"行为特征合并: {fam_key}（现 {behs_n} 项行为）")

    rule_name, strs_written = None, 0
    try:
        data = Path(result["path"]).read_bytes()
        rule_text, strs = _build_rule(result, data)
        if rule_text:
            rule_name = _rule_name(result, sha)
            ok, msg = _append_rule(rules_dir or RULES_DIR, rule_text, rule_name)
            strs_written = len(strs)
            notes.append(f"YARA 规则{rule_name}: {msg}"
                         + (f"（{strs_written} 个特征串）" if ok else ""))
        else:
            notes.append("特征串不足 2 条，不生成 YARA 规则")
    except OSError as exc:
        notes.append(f"规则生成失败: {exc}")

    return {"learned": True, "hashes": added, "rule": rule_name,
            "strings": strs_written, "behaviors": sorted(behaviors),
            "category": cat, "notes": notes}


def format_summary(s):
    """渲染学习摘要为终端文本。"""
    if not s["learned"]:
        return "[i] 自动学习: " + "; ".join(s["notes"])
    lines = [f"[+] 自动学习完成: 哈希入库 {', '.join(s['hashes']) or '无新增'}"
             + (f"，规则 {s['rule']}（{s['strings']} 串）" if s["rule"] else "")]
    if s.get("behaviors"):
        lines[0] += (f"，行为特征 {len(s['behaviors'])} 项"
                     f"（{s.get('category') or 'Malware'}）")
    lines += [f"    - {n}" for n in s["notes"]]
    return "\n".join(lines)
