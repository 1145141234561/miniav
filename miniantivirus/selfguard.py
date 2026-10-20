"""自保护：MiniAV 自身与特征库的完整性基线 + 篡改校验。

对关键文件（exe / signatures.json / 规则 / 缓存无关项）做 sha256 基线，
guard check 对比发现 missing / modified / new 三类变化。
签名库经工具自身 save_db 更新时自动刷新基线条目，避免误报。
"""

import hashlib
import json
import time
from pathlib import Path

from .signatures import APP_DIR, RULES_DIR, SIG_DB


class GuardError(ValueError):
    pass


def MANIFEST():
    return APP_DIR / "guard_manifest.json"


def _default_targets():
    """默认保护对象：签名库 + 全部规则文件（exe 由 extra 指定）。"""
    targets = [SIG_DB]
    if RULES_DIR.is_dir():
        targets += sorted(p for p in RULES_DIR.glob("*") if p.is_file())
    return [p for p in targets if p.is_file()]


def _digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def baseline(extra=None):
    """生成完整性基线，返回 manifest dict。"""
    files = _default_targets() + [Path(p) for p in (extra or [])]
    manifest = {
        "type": "miniantivirus-guard",
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "files": {},
    }
    for p in files:
        p = Path(p)
        if p.is_file():
            try:
                manifest["files"][str(p)] = {
                    "sha256": _digest(p), "size": p.stat().st_size}
            except OSError:
                continue
    MANIFEST().write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    return manifest


def update_entry(path):
    """单文件基线条目刷新（save_db 更新签名库后调用；无基线时忽略）。"""
    m = MANIFEST()
    if not m.is_file():
        return
    try:
        manifest = json.loads(m.read_text(encoding="utf-8"))
        p = Path(path)
        if str(p) in manifest.get("files", {}) and p.is_file():
            manifest["files"][str(p)] = {"sha256": _digest(p),
                                         "size": p.stat().st_size}
            m.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8")
    except (OSError, ValueError):
        pass


def check(extra=None, with_new=None):
    """对比基线，返回 {missing, modified, new, ok_count}。

    with_new: 额外目录，基线外的文件在其中按 new 报告。
    """
    m = MANIFEST()
    if not m.is_file():
        raise GuardError("尚未建立基线，请先运行 guard baseline")
    manifest = json.loads(m.read_text(encoding="utf-8"))
    res = {"missing": [], "modified": [], "new": [], "ok_count": 0}
    for path_s, info in manifest.get("files", {}).items():
        p = Path(path_s)
        if not p.is_file():
            res["missing"].append(path_s)
            continue
        if _digest(p) != info.get("sha256"):
            res["modified"].append(path_s)
        else:
            res["ok_count"] += 1
    for d in (with_new or []):
        d = Path(d)
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*")):
            if p.is_file() and str(p) not in manifest.get("files", {}):
                res["new"].append(str(p))
    return res


def format_report(res, exe_signed=None):
    L = [f"自保护校验: 完好 {res['ok_count']} · 被篡改 {len(res['modified'])} · "
         f"缺失 {len(res['missing'])} · 新增 {len(res['new'])}"]
    for x in res["modified"]:
        L.append(f"  [HIGH] 被篡改: {x}")
    for x in res["missing"]:
        L.append(f"  [MEDIUM] 缺失: {x}")
    for x in res["new"]:
        L.append(f"  [LOW] 基线外新增: {x}")
    if exe_signed is not None:
        L.append(f"  自身 EXE 数字签名: {exe_signed}")
    verdict = (not res["modified"] and not res["missing"])
    L.append(f"[i] 结论: {'完整性正常' if verdict else '检测到异常，请排查上述文件'}")
    return "\n".join(L)
