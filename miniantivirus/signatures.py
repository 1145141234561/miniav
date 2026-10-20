"""签名库读写与全局路径定义。"""

import fnmatch
import json
import shutil
import sys
from pathlib import Path

# 打包成 exe 后数据文件放在 exe 同目录（可写、可持久化）；源码运行时用项目根
if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).resolve().parent
else:
    APP_DIR = Path(__file__).resolve().parent.parent
SIG_DB = APP_DIR / "signatures.json"
QUAR_DIR = APP_DIR / "quarantine"
SCAN_LOG = APP_DIR / "scan.log"
RULES_DIR = APP_DIR / "rules"
VT_CACHE = APP_DIR / "vt_cache.json"
MAX_CONTENT_SCAN = 64 * 1024 * 1024  # 超过 64MB 的文件只做哈希，不做内容匹配

DEFAULT_DB = {
    "version": 3,
    "hashes": {"md5": {}, "sha1": {}, "sha256": {}},
    "patterns": [],
    "exclusions": ["*.pyc", "*.yar", "*.yara"],
    "whitelist": {},
    "behaviors": {},
}


def ensure_data_files():
    """frozen 打包环境自举：首次运行把内置签名库/规则释放到 exe 目录。"""
    if not getattr(sys, "frozen", False):
        return
    meipass = getattr(sys, "_MEIPASS", None)
    if not meipass:
        return
    src = Path(meipass)
    if not SIG_DB.exists() and (src / "signatures.json").is_file():
        shutil.copy2(src / "signatures.json", SIG_DB)
    if not RULES_DIR.exists() and (src / "rules").is_dir():
        shutil.copytree(src / "rules", RULES_DIR)


def default_db():
    return json.loads(json.dumps(DEFAULT_DB))


def normalize_db(db):
    """兼容旧版签名库：补齐缺失段，返回归一化后的库。"""
    if not isinstance(db, dict):
        return default_db()
    db.setdefault("version", 3)
    hashes = db.setdefault("hashes", {})
    if not isinstance(hashes, dict):
        db["hashes"] = default_db()["hashes"]
    else:
        for algo in ("md5", "sha1", "sha256"):
            if not isinstance(hashes.get(algo), dict):
                hashes[algo] = {}
    if not isinstance(db.get("patterns"), list):
        db["patterns"] = []
    for sig in db["patterns"]:
        # 旧版 regex 模式用 "pattern" 键存内容，统一迁移为 "data"
        if isinstance(sig, dict) and "data" not in sig and "pattern" in sig:
            sig["data"] = sig.pop("pattern")
    if not isinstance(db.get("whitelist"), dict):
        db["whitelist"] = {}
    if not isinstance(db.get("vulnerable_drivers"), dict):
        db["vulnerable_drivers"] = {}
    behs = db.get("behaviors")
    if not isinstance(behs, dict):
        db["behaviors"] = {}
    else:   # 丢弃损坏条目（家族名 → 元信息 dict）
        for k in [k for k, v in behs.items() if not isinstance(v, dict)]:
            behs.pop(k)
    return db


def load_db():
    try:
        return normalize_db(json.loads(SIG_DB.read_text(encoding="utf-8")))
    except FileNotFoundError:
        sys.exit(f"签名库缺失: {SIG_DB}")
    except json.JSONDecodeError as exc:
        sys.exit(f"签名库不是合法 JSON: {exc}")


def save_db(db):
    SIG_DB.write_text(json.dumps(db, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        # 自保护联动：签名库经工具合法更新后刷新基线条目（无基线时忽略）
        from . import selfguard
        selfguard.update_entry(SIG_DB)
    except Exception:
        pass


def is_excluded(path, excludes):
    """fnmatch 匹配完整路径或文件名（不区分大小写）。"""
    if not excludes:
        return False
    s = str(path).lower()
    name = Path(s).name
    for pat in excludes:
        p = str(pat).lower()
        if fnmatch.fnmatch(s, p) or fnmatch.fnmatch(name, p):
            return True
    return False
