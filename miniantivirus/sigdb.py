"""签名库管理核心逻辑：增删查/统计/导入导出（CLI 与 GUI 共用）。

签名库 JSON 结构（version 3）：
  hashes.md5 / hashes.sha1 / hashes.sha256: {摘要: {"name": str, "level": str}}
  patterns: [{"type": "regex"|"hex", "data": str, "name": str, "level": str}]
  exclusions: [glob]; whitelist: {sha256: {...}}; vulnerable_drivers: {sha256: {...}}
"""

import re

_ALGO_LEN = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_LEVELS = ("high", "medium", "low")


class SigdbError(ValueError):
    """签名操作参数错误（CLI/GUI 显示给用户的用户可读消息）。"""


def _norm_level(level):
    lv = str(level or "high").lower()
    return lv if lv in _LEVELS else "high"


def _norm_hex(value, algo=None):
    v = str(value).strip().lower().replace(" ", "")
    if algo:
        if algo not in _ALGO_LEN:
            raise SigdbError(f"不支持的算法: {algo}（可选 md5/sha1/sha256）")
        if len(v) != _ALGO_LEN[algo] or not _HEX_RE.match(v):
            raise SigdbError(f"{algo} 摘要应为 {_ALGO_LEN[algo]} 位十六进制")
        return algo, v
    for a, n in _ALGO_LEN.items():
        if len(v) == n and _HEX_RE.match(v):
            return a, v
    raise SigdbError("无法识别的哈希（应为 32/40/64 位十六进制）")


# ---------------------------------------------------------------- 增删

def add_hash(db, value, name, level="high", algo=None):
    """添加哈希签名，返回 (algo, 摘要, 是否新增)。"""
    algo, digest = _norm_hex(value, algo)
    if not str(name or "").strip():
        raise SigdbError("签名名称不能为空")
    meta = {"name": str(name).strip(), "level": _norm_level(level)}
    hashes = db["hashes"]
    # 同一摘要若已存在于另一算法段，同步补齐到该段，保持三段一致
    existed = any(digest in hashes[a] for a in _ALGO_LEN if a != algo)
    seg = hashes[algo]
    is_new = digest not in seg
    seg[digest] = meta
    return algo, digest, is_new and not existed


def add_sample(db, path, name=None, level="high"):
    """从样本文件添加签名：自动计算三算法摘要并写入，返回 (摘要组, 是否新增)。"""
    from .scanner import hash_all
    try:
        hashes = hash_all(path)
    except OSError as exc:
        raise SigdbError(f"无法读取样本: {exc}")
    label = str(name or "").strip() or path.stem or "Unknown"
    is_new = hashes["sha256"] not in db["hashes"]["sha256"]
    meta = {"name": label, "level": _norm_level(level)}
    for algo, digest in hashes.items():
        db["hashes"][algo][digest] = dict(meta)
    return hashes, is_new


def remove_hash(db, value):
    """删除哈希签名（三算法段一并清理），返回删除的算法列表。"""
    _algo, digest = _norm_hex(value)
    removed = []
    for algo in _ALGO_LEN:
        if digest in db["hashes"][algo]:
            del db["hashes"][algo][digest]
            removed.append(algo)
    if not removed:
        raise SigdbError(f"未找到该哈希: {digest}")
    return removed


def add_pattern(db, ptype, data, name, level="medium"):
    """添加模式签名（regex / hex），返回是否新增。"""
    ptype = str(ptype or "").lower()
    if ptype not in ("regex", "hex"):
        raise SigdbError("模式类型应为 regex 或 hex")
    data = str(data or "").strip()
    if not data:
        raise SigdbError("模式内容不能为空")
    if ptype == "hex":
        data = data.replace(" ", "").lower()
        try:
            bytes.fromhex(data)
        except ValueError as exc:
            raise SigdbError(f"非法十六进制模式: {exc}")
    elif ptype == "regex":
        try:
            re.compile(data)
        except re.error as exc:
            raise SigdbError(f"非法正则表达式: {exc}")
    if not str(name or "").strip():
        raise SigdbError("签名名称不能为空")
    entry = {"type": ptype, "data": data, "name": str(name).strip(),
             "level": _norm_level(level)}
    if entry in db["patterns"]:
        return False
    db["patterns"].append(entry)
    return True


def remove_pattern(db, index):
    """按下标删除模式签名，返回被删条目。"""
    try:
        return db["patterns"].pop(int(index))
    except (IndexError, ValueError):
        raise SigdbError(f"模式序号无效: {index}")


# ---------------------------------------------------------------- 查询/统计

def iter_hashes(db):
    """去重枚举哈希签名（同一恶意样本通常三算法并存，按名称+级别归并）。

    产出 (algo, digest, name, level)。
    """
    for algo in ("md5", "sha1", "sha256"):
        for digest, meta in db["hashes"].get(algo, {}).items():
            if isinstance(meta, dict):
                yield algo, digest, meta.get("name", "Unknown"), meta.get("level", "high")
            else:  # 兼容旧库字符串值
                yield algo, digest, str(meta), "high"


def stats(db):
    hashes = db.get("hashes", {})
    return {
        "md5": len(hashes.get("md5", {})),
        "sha1": len(hashes.get("sha1", {})),
        "sha256": len(hashes.get("sha256", {})),
        "patterns": len(db.get("patterns", [])),
        "whitelist": len(db.get("whitelist", {})),
        "vulnerable_drivers": len(db.get("vulnerable_drivers", {})),
        "exclusions": len(db.get("exclusions", [])),
    }


# ---------------------------------------------------------------- 导入导出

_CSV_HEADER = ("algo", "hash", "name", "level")


def export_file(db, dest_path, fmt="json"):
    """导出签名库。json=完整库快照；csv=哈希+模式签名平面表。返回导出条数。"""
    import csv
    import json as _json
    from pathlib import Path
    dest = Path(dest_path)
    fmt = str(fmt or "json").lower()
    if fmt == "json":
        dest.write_text(_json.dumps(db, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
        s = stats(db)
        return s["md5"] + s["sha1"] + s["sha256"] + s["patterns"]
    if fmt in ("csv", "txt"):
        n = 0
        with open(dest, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(_CSV_HEADER)
            for algo, digest, name, level in iter_hashes(db):
                w.writerow((algo, digest, name, level))
                n += 1
            for sig in db.get("patterns", []):
                w.writerow((sig.get("type", "regex"), sig.get("data", ""),
                            sig.get("name", "Unknown"), sig.get("level", "medium")))
                n += 1
        return n
    raise SigdbError(f"不支持的导出格式: {fmt}（json/csv）")


def import_file(db, src_path):
    """导入签名库并合并去重。支持完整库 JSON 或 CSV 平面表。

    返回 {"hashes": 新增哈希数, "patterns": 新增模式数, "skipped": 跳过数}。
    """
    import csv
    import json as _json
    from pathlib import Path
    src = Path(src_path)
    added = {"hashes": 0, "patterns": 0, "skipped": 0}
    text = src.read_text(encoding="utf-8-sig", errors="replace")

    if src.suffix.lower() == ".json" or text.lstrip().startswith(("{", "[")):
        try:
            data = _json.loads(text)
        except _json.JSONDecodeError as exc:
            raise SigdbError(f"JSON 解析失败: {exc}")
        if isinstance(data, list):
            data = {"patterns": [p for p in data if isinstance(p, dict)]}
        if not isinstance(data, dict):
            raise SigdbError("JSON 内容应为签名库对象或签名列表")

        imported = data.get("hashes")
        if isinstance(imported, dict):
            for algo, seg in imported.items():
                if algo not in _ALGO_LEN or not isinstance(seg, dict):
                    added["skipped"] += 1
                    continue
                for digest, meta in seg.items():
                    try:
                        _a, _d, is_new = add_hash(db, digest, str(meta),
                                                  level="high", algo=algo)
                    except SigdbError:
                        added["skipped"] += 1
                        continue
                    # add_hash 对旧字符串值兼容：meta 为 str 时转 dict
                    entry = db["hashes"][algo][_norm_hex(digest, algo)[1]]
                    if isinstance(meta, dict):
                        entry.update({"name": str(meta.get("name", entry["name"])),
                                      "level": _norm_level(meta.get("level", entry["level"]))})
                    if is_new:
                        added["hashes"] += 1
        for sig in data.get("patterns", []):
            if not isinstance(sig, dict):
                added["skipped"] += 1
                continue
            try:
                if add_pattern(db, sig.get("type"), sig.get("data"),
                               sig.get("name"), sig.get("level")):
                    added["patterns"] += 1
            except SigdbError:
                added["skipped"] += 1
        # 可选段：白名单 / 漏洞驱动黑名单合并
        for key in ("whitelist", "vulnerable_drivers"):
            extra = data.get(key)
            if isinstance(extra, dict):
                target = db.setdefault(key, {})
                for k, v in extra.items():
                    if k not in target:
                        target[k] = v
                        added["hashes"] += 0  # 不计入哈希统计，仅合并
        return added

    # CSV 平面表
    rows = list(csv.reader(text.splitlines()))
    for i, row in enumerate(rows):
        if not row or (i == 0 and [c.strip().lower() for c in row[:2]] == list(_CSV_HEADER[:2])):
            continue
        kind = row[0].strip().lower()
        try:
            if kind in _ALGO_LEN:
                _a, _d, is_new = add_hash(db, row[1], row[2], level=row[3] if len(row) > 3 else "high")
                if is_new:
                    added["hashes"] += 1
            elif kind in ("regex", "hex"):
                if add_pattern(db, kind, row[1], row[2],
                               row[3] if len(row) > 3 else "medium"):
                    added["patterns"] += 1
            else:
                added["skipped"] += 1
        except SigdbError:
            added["skipped"] += 1
    return added
