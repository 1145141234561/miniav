"""离线特征包：签名库 + YARA 规则打成单个 zip，供隔离环境离线扫描。

包结构（zip 根目录）：
  manifest.json    {"type": "miniantivirus-pack", "version", "created", "counts"}
  signatures.json  完整签名库
  rules/<name>     YARA 规则文件（.yar/.yara）

安全约束：条目名白名单、解压总预算与条目数上限（防压缩炸弹）、
规则文件仅按 basename 写入专用临时目录（防 zip-slip）。
"""

import json
import tempfile
import time
import zipfile
from pathlib import Path

from .signatures import RULES_DIR, SIG_DB, default_db, normalize_db

MANIFEST = "manifest.json"
MAX_TOTAL = 16 * 1024 * 1024   # 解压总预算 16MB
MAX_ENTRIES = 64               # 条目数上限


class PackError(ValueError):
    """特征包格式/安全校验错误（用户可读消息）。"""


def export_pack(dest, db_path=None, rules_dir=None):
    """打包签名库与规则目录，返回 (包路径, manifest dict)。"""
    db_path = Path(db_path) if db_path else SIG_DB
    rules_dir = Path(rules_dir) if rules_dir else RULES_DIR
    db = normalize_db(json.loads(db_path.read_text(encoding="utf-8")))
    rules = sorted(p for p in rules_dir.glob("*")
                   if p.suffix.lower() in (".yar", ".yara")) if rules_dir.is_dir() else []
    manifest = {
        "type": "miniantivirus-pack",
        "version": db.get("version", 3),
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hashes": sum(len(v) for v in db["hashes"].values()),
        "patterns": len(db.get("patterns", [])),
        "rules": [p.name for p in rules],
    }
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(MANIFEST, json.dumps(manifest, ensure_ascii=False, indent=2))
        zf.write(db_path, "signatures.json")
        for p in rules:
            zf.write(p, f"rules/{p.name}")
    return dest, manifest


def _check_zip_safety(zf):
    """条目数/累计解压大小预算校验（防压缩炸弹）。"""
    names = zf.namelist()
    if len(names) > MAX_ENTRIES:
        raise PackError(f"包内条目数超限: {len(names)} > {MAX_ENTRIES}")
    total = sum(i.file_size for i in zf.infolist())
    if total > MAX_TOTAL:
        raise PackError(f"解压总大小超预算: {total:,} > {MAX_TOTAL:,} 字节")
    return names


def load_pack(src):
    """读取特征包，返回 (db, rules, manifest)；rules 为 [(文件名, 字节), ...]。

    条目名白名单：manifest.json / signatures.json / rules/<basename>.yar[a]，
    其余条目一律拒绝（防路径逃逸与陌生内容）。
    """
    src = Path(src)
    if not src.is_file():
        raise PackError(f"特征包不存在: {src}")
    db = rules = manifest = None
    rule_bytes = []
    try:
        with zipfile.ZipFile(src) as zf:
            names = _check_zip_safety(zf)
            for info in zf.infolist():
                name = Path(info.filename).as_posix()
                if name in (MANIFEST, "signatures.json"):
                    data = zf.read(info)
                    obj = json.loads(data.decode("utf-8"))
                    if name == MANIFEST:
                        manifest = obj
                    else:
                        db = obj
                elif (name.startswith("rules/")
                      and "/" not in name[len("rules/"):].replace("\\", "/")
                      and info.filename.split("/")[-1].split(".")[-1].lower()
                      in ("yar", "yara")):
                    rule_bytes.append(
                        (info.filename.split("/")[-1], zf.read(info)))
                else:
                    raise PackError(f"包内存在非法条目: {name}")
    except zipfile.BadZipFile as exc:
        raise PackError(f"特征包不是合法 zip: {exc}")
    if db is None:
        raise PackError("包内缺少 signatures.json")
    manifest = manifest or {}
    rules = rule_bytes
    return normalize_db(db), rules, manifest


def extract_rules_temp(rules):
    """把包内规则写入一次性临时目录，返回目录路径（供 ScanContext 使用）。"""
    tmp = Path(tempfile.mkdtemp(prefix="miniav_pack_rules_"))
    for name, data in rules:
        safe = Path(name).name  # 仅 basename，防 zip-slip
        (tmp / safe).write_bytes(data)
    return tmp


def pack_info(src):
    """特征包摘要信息（pack info 子命令用）。"""
    _db, rules, manifest = load_pack(src)
    info = dict(manifest)
    info["rule_files"] = [n for n, _ in rules]
    info["rule_count"] = len(rules)
    return info
