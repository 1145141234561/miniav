"""zip 压缩包扫描：内存解包 + 预算/深度/压缩比防护 + 递归嵌套。

安全设计：全程在内存中读取条目，绝不解压到磁盘（天然免疫 zip-slip）；
用解压预算、条目上限与压缩比阈值抵御 zip 炸弹。
"""

import hashlib
import io
import zipfile
from pathlib import Path

from .scanner import content_findings, pe_heuristics
from .signatures import is_excluded

MAX_ENTRY = 32 * 1024 * 1024    # 单条目解压上限 32MB
MAX_TOTAL = 512 * 1024 * 1024   # 单压缩包累计解压预算 512MB
MAX_DEPTH = 3                   # 嵌套 zip 最大层数
MAX_RATIO = 100                 # 解压/压缩比阈值（zip 炸弹迹象）


def _tag(findings, inner):
    """给检出记录的 detail 加上 zip 内部路径前缀。"""
    out = []
    for fd in findings:
        fd = dict(fd)
        fd["detail"] = f"zip:{inner} — {fd.get('detail', '')}"
        out.append(fd)
    return out


def scan_zip(path, db, ctx=None, depth=0, prefix=None):
    path = Path(path)
    with open(path, "rb") as fh:
        return _scan_zip_obj(fh, db, ctx, depth=depth, prefix=prefix or path.name)


def _scan_zip_obj(fileobj, db, ctx=None, depth=0, prefix="archive"):
    findings = []
    if depth > MAX_DEPTH:
        return [{"name": "Zip-Too-Deep", "level": "medium",
                 "detail": f"{prefix}: 嵌套超过 {MAX_DEPTH} 层，停止解包"}]
    budget = MAX_TOTAL
    with zipfile.ZipFile(fileobj) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            inner = f"{prefix}!{name}"
            if ctx and ctx.excludes and is_excluded(name, ctx.excludes):
                continue
            if info.file_size > MAX_ENTRY:
                findings.append({"name": "Zip-Entry-Too-Large", "level": "low",
                                 "detail": f"{inner}: 条目解压后超过 {MAX_ENTRY // (1024 * 1024)}MB 上限，跳过"})
                continue
            if info.file_size > budget:
                findings.append({"name": "Zip-Budget-Exceeded", "level": "medium",
                                 "detail": f"{inner}: 累计解压预算耗尽，停止解包"})
                break
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > MAX_RATIO:
                findings.append({"name": "Zip-Suspect-Ratio", "level": "medium",
                                 "detail": f"{inner}: 压缩比 {ratio:.0f}:1 异常（zip 炸弹迹象），跳过"})
                continue
            try:
                data = zf.read(info)
            except (zipfile.BadZipFile, RuntimeError, OSError):
                continue
            budget -= len(data)

            findings += _tag(_scan_bytes(data, db, ctx), inner)

            if data[:2] == b"PK":
                findings += _scan_zip_obj(io.BytesIO(data), db, ctx,
                                          depth=depth + 1, prefix=inner)
    return findings


def _scan_bytes(data, db, ctx):
    """对单个解压条目做 哈希/白名单/内容/PE 检测（VT 信誉只查顶层文件）。"""
    out = []
    sha = hashlib.sha256(data).hexdigest()
    if ctx and sha in ctx.whitelist:
        return out
    hit = db.get("hashes", {}).get("sha256", {}).get(sha)
    if hit:
        out.append({"name": hit.get("name", "Unknown"),
                    "level": hit.get("level", "high"),
                    "detail": "sha256 哈希精确匹配"})
    out += content_findings(data, db, ctx)
    if data[:2] == b"MZ":
        heur = pe_heuristics(data)
        if heur:
            out.append(heur)
    return out
