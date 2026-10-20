"""命令行入口：解析参数并分发到各子命令。"""

import argparse
import json
import re
import shutil
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from . import analyzer, autoruns, pack, procscan, report, sandbox, scanner
from .scanner import ScanContext, _in_quarantine, quarantine_file, scan_file
from .signatures import RULES_DIR, SCAN_LOG, load_db, save_db


def build_ctx(args, db):
    """根据命令行参数构造 ScanContext（YARA 规则默认自动加载 rules/ 目录）。"""
    rules = []
    want = getattr(args, "rules", None)
    if want:
        p = Path(want)
        if p.is_dir():
            rules = sorted(str(x) for x in
                           list(p.glob("*.yar")) + list(p.glob("*.yara")))
        elif p.is_file():
            rules = [str(p)]
        else:
            sys.exit(f"规则路径不存在: {p}")
    elif RULES_DIR.exists():
        rules = sorted(str(x) for x in
                       list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara")))
    if rules and not scanner.HAS_YARA:
        print("[!] 检测到 YARA 规则但未安装 yara-python，忽略规则"
              "（python -m pip install yara-python）")
        rules = []

    vt = bool(getattr(args, "vt", False))
    if vt:
        from .vt import VTClient
        if not VTClient.has_key():
            print("[!] 未设置 VT_API_KEY 环境变量，跳过哈希信誉查询")
            vt = False

    excludes = list(db.get("exclusions", [])) + list(getattr(args, "exclude", None) or [])
    return ScanContext(rules_paths=rules,
                       excludes=excludes,
                       whitelist=dict(db.get("whitelist", {})),
                       vt=vt,
                       sigcheck=bool(getattr(args, "sigcheck", False)),
                       fast=bool(getattr(args, "fast", False)))


def _scan_worker(payload):
    """子进程入口：ScanContext 按路径惰性编译 YARA，规避 Rules 不可 pickle。"""
    path, db, spec = payload
    ctx = ScanContext.from_spec(spec)
    return path, scan_file(Path(path), db, ctx)


def cmd_scan(args):
    db = load_db()
    target = Path(args.path)
    if not target.exists():
        sys.exit(f"路径不存在: {target}")
    ctx = build_ctx(args, db)
    if target.is_file():
        files = [target]
    else:
        files = sorted(p for p in target.rglob("*")
                       if p.is_file() and not _in_quarantine(p))

    stats = {"scanned": 0, "detected": 0}
    rows = []

    def emit(path_str, fds):
        p = Path(path_str)
        stats["scanned"] += 1
        for fd in fds:
            if fd.get("level") == "error":
                print(f"[!] {p}: {fd['name']}")
                continue
            stats["detected"] += 1
            rows.append({"path": str(p), **fd})
            print(f"[x] {p}: [{fd['level'].upper()}] {fd['name']} — "
                  f"{fd.get('detail', '')}")
        if args.quarantine:
            high = next((fd for fd in fds if fd.get("level") == "high"), None)
            if high:
                try:
                    qn = quarantine_file(p, high)
                    print(f"    -> 已隔离: {qn}")
                except OSError as exc:
                    print(f"[!] 隔离失败 {p}: {exc}")

    jobs = max(1, getattr(args, "jobs", 1) or 1)
    if jobs > 1 and len(files) > 1:
        spec = ctx.to_spec()
        with ProcessPoolExecutor(max_workers=jobs) as ex:
            for path_str, fds in ex.map(_scan_worker,
                                        [(str(f), db, spec) for f in files],
                                        chunksize=4):
                emit(path_str, fds)
    else:
        for f in files:
            emit(str(f), scan_file(f, db, ctx))

    print(f"\n[i] 扫描完成: {stats['scanned']} 个文件, {stats['detected']} 条检出。")
    if getattr(args, "fast", False):
        scanner.flush_cache()
        if scanner.cache_hits():
            print(f"[i] 增量缓存命中 {scanner.cache_hits()} 个未变更文件。")
    if args.report:
        out = report.write_html(args.report, {
            "target": str(target),
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "files": stats["scanned"], "findings": stats["detected"]}, rows)
        print(f"[i] HTML 报告已生成: {out}")
    try:
        with open(SCAN_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] scan={target} "
                     f"files={stats['scanned']} findings={stats['detected']}\n")
    except OSError:
        pass
    return 1 if stats["detected"] else 0


def cmd_watch(args):
    from . import watcher
    db = load_db()
    ctx = build_ctx(args, db)
    try:
        stats = watcher.watch(args.path, db, ctx, quarantine=args.quarantine)
    except RuntimeError as exc:
        sys.exit(f"[!] {exc}")
    print(f"\n[i] 监视结束: 扫描 {stats['scanned']} 次, "
          f"检出 {stats['findings']} 条, 隔离 {stats['quarantined']} 个。")
    return 0


def cmd_vt(args):
    from .vt import VTClient, finding_from_stats
    if not VTClient.has_key():
        sys.exit("[!] 未设置 VT_API_KEY 环境变量（https://www.virustotal.com 免费申请）")
    t = args.target
    if getattr(args, "upload", False):
        f = Path(t)
        if not f.is_file():
            sys.exit(f"文件不存在: {f}")
        print(f"[i] 上传到 VirusTotal 多引擎扫描: {f}")
        print("[i] 注意：文件内容将被公开共享（免费接口单文件 ≤32MB）")
        try:
            stats = VTClient.shared().upload(f)
        except RuntimeError as exc:
            print(f"[!] {exc}")
            return 1
        print(f"[i] 引擎统计: malicious={stats.get('malicious', 0)} "
              f"suspicious={stats.get('suspicious', 0)} "
              f"undetected={stats.get('undetected', 0)} "
              f"harmless={stats.get('harmless', 0)}")
        fd = finding_from_stats(stats)
        if fd:
            print(f"[x] [{fd['level'].upper()}] {fd['name']} — {fd['detail']}")
        else:
            print("[i] 各引擎未见可疑报告。")
        return 0
    if re.fullmatch(r"[0-9a-fA-F]{64}", t):
        sha = t.lower()
    else:
        f = Path(t)
        if not f.is_file():
            sys.exit(f"文件不存在: {f}")
        _m, sha = scanner.file_hashes(f)
    print(f"[i] 查询 VirusTotal: {sha}")
    try:
        stats = VTClient.shared().query(sha)
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return 1
    if stats is None:
        print("[i] VT 库中无此样本记录（未被上传分析过）。")
        return 0
    print(f"[i] 引擎统计: malicious={stats.get('malicious', 0)} "
          f"suspicious={stats.get('suspicious', 0)} "
          f"undetected={stats.get('undetected', 0)} "
          f"harmless={stats.get('harmless', 0)}")
    fd = finding_from_stats(stats)
    if fd:
        print(f"[x] [{fd['level'].upper()}] {fd['name']} — {fd['detail']}")
    else:
        print("[i] 社区未见可疑报告。")
    return 0


def cmd_analyze(args):
    """样本深度分析：任意文件一键静态体检（绝不执行样本）。"""
    f = Path(args.path)
    if not f.is_file():
        sys.exit(f"文件不存在: {f}")
    db = load_db()
    rules = []
    want = getattr(args, "rules", None)
    if want:
        rules = [str(x) for x in _collect_rule_files(want)]
    elif RULES_DIR.exists():
        rules = [str(x) for x in _collect_rule_files(None)]
    ctx = ScanContext(rules_paths=rules, whitelist=db.get("whitelist", {}))
    result = analyzer.analyze_sample(f, db, ctx=ctx,
                                     vt=getattr(args, "vt", False))
    print(analyzer.format_report(result))

    if getattr(args, "learn", False):
        from . import autolearn
        ls = autolearn.learn_from_result(result, db)
        if ls["learned"]:
            save_db(db)
        print(autolearn.format_summary(ls))

    if getattr(args, "json", None):
        Path(args.json).write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[i] JSON 报告已写入: {args.json}")
    if getattr(args, "html", None):
        rows = [{"path": result["path"], **fd} for fd in result["findings"]
                if fd.get("level") in analyzer._LEVEL_WEIGHT]
        b = result.get("behavior")
        if b:
            for h in b["hits"]:
                rows.append({"path": result["path"], "name": h["name"],
                             "level": "high" if h["weight"] >= 2 else "medium",
                             "detail": f"行为特征: {h['desc']}"})
        report.write_html(args.html, {"target": str(f), "files": 1,
                                      "findings": len(rows),
                                      "time": time.strftime("%Y-%m-%d %H:%M:%S")},
                          rows)
        print(f"[i] HTML 报告已写入: {args.html}")
    return 0 if result["verdict"] == "清洁" else 1


def cmd_procs(args):
    """进程安全检查：运行进程快照的签名/落位/伪装/哈希黑名单核查。"""
    rows, stats = procscan.scan_processes(load_db())
    print(procscan.format_report(rows, stats))
    return 1 if stats["suspicious"] else 0


def cmd_autoruns(args):
    """启动项安全检查：注册表/启动文件夹/计划任务/服务的可疑持久化项。"""
    rows, stats = autoruns.scan_autoruns()
    print(autoruns.format_report(rows, stats))
    bad = sum(1 for r in rows if r["level"] in ("high", "medium"))
    return 1 if bad else 0


def cmd_guard(args):
    """自保护：完整性基线（baseline）与篡改校验（check）。"""
    from . import selfguard, wintrust
    exe = Path(sys.executable) if getattr(sys, "frozen", False) else None
    if args.guardcmd == "baseline":
        targets = [exe] if exe and exe.is_file() else None
        mf = selfguard.baseline(extra=targets)
        print(f"[+] 完整性基线已建立: {selfguard.MANIFEST()}")
        print(f"    保护文件 {len(mf['files'])} 个 · 生成时间 {mf['created']}")
        print("[i] 建议将 guard_manifest.json 复制到只读位置防基线本身被篡改")
        return 0
    if not selfguard.MANIFEST().is_file():
        sys.exit("尚未建立基线，请先运行: miniantivirus.py guard baseline")
    exe_signed = None
    if exe and exe.is_file() and wintrust.HAS_WINTRUST:
        exe_signed = wintrust.verify_embedded(str(exe))[0]
    res = selfguard.check()
    print(selfguard.format_report(res, exe_signed))
    return 0 if not (res["modified"] or res["missing"]) else 1


def cmd_defend(args):
    """用户态进程自保护：DACL 加固 + 双进程互守护（无需驱动/管理员）。"""
    from . import processguard
    if args.defendcmd == "__worker":
        processguard.worker_loop(getattr(args, "state", None))
        return 0
    if args.defendcmd == "start":
        return processguard.run_daemonized(
            watch_dir=getattr(args, "watch", None),
            use_dacl=not getattr(args, "no_dacl", False))
    if args.defendcmd == "stop":
        return processguard.guard_stop()
    return processguard.guard_status()


def cmd_protect(args):
    """进程自保护：MiniAVProt 内核驱动剥离对受保护进程的危险句柄权限。"""
    from . import driverprotect
    if getattr(args, "install", False):
        d2, err2 = driverprotect.ensure_loaded()
        if d2 is None:
            print(f"[!] 自动加载失败: {err2}")
            print("    （Secure Boot 开启时测试签名驱动无法加载，"
                  "可改用用户态方案: python -m miniantivirus defend start）")
            return 1
        print("[+] 驱动自动加载完成: " + ("已启用" if d2["enabled"] else "已停用"))
    try:
        if getattr(args, "name", None):
            driverprotect.set_name(args.name)
            print(f"[+] 已设置受保护镜像名: {args.name}")
        if getattr(args, "on", False):
            driverprotect.enable(True)
            print("[+] 进程保护已启用")
        if getattr(args, "off", False):
            driverprotect.enable(False)
            print("[-] 进程保护已停用")
    except PermissionError as exc:
        print(f"[!] {exc}")
        return 1
    except driverprotect.DriverError as exc:
        print(f"[!] {exc}")
        print("    " + driverprotect.LOAD_HINT.replace("\n", "\n    "))
        return 1
    d, err = driverprotect.safe_status()
    if d is None:
        print(f"[!] 无法查询驱动状态: {err}")
        print("    " + driverprotect.LOAD_HINT.replace("\n", "\n    "))
        return 1
    print(driverprotect.format_report(d))
    return 0 if d["enabled"] else 1


def cmd_pack(args):
    """离线特征包管理：export / info。"""
    if args.packcmd == "export":
        dest, manifest = pack.export_pack(args.file)
        print(f"[+] 特征包已导出: {dest}")
        print(f"    哈希签名 {manifest['hashes']} · 模式签名 {manifest['patterns']} "
              f"· 规则文件 {len(manifest['rules'])}")
        return 0
    info = pack.pack_info(args.file)
    print(f"特征包: {args.file}")
    print(f"  版本 v{info.get('version', '?')} · 生成时间 {info.get('created', '?')}")
    print(f"  哈希 {info.get('hashes', 0)} · 模式 {info.get('patterns', 0)} · "
          f"规则 {info.get('rule_count', 0)} 个: "
          f"{', '.join(info.get('rule_files', [])) or '-'}")
    return 0


def cmd_offline(args):
    """离线扫描：全部本地引擎，全程不访问网络（--pack 指定离线特征包）。"""
    target = Path(args.path)
    if not target.exists():
        sys.exit(f"路径不存在: {target}")
    tmp_rules = None
    if getattr(args, "pack", None):
        try:
            db, rules_bytes, _mf = pack.load_pack(args.pack)
        except pack.PackError as exc:
            sys.exit(f"[!] {exc}")
        if rules_bytes:
            tmp_rules = pack.extract_rules_temp(rules_bytes)
            rules = sorted(str(p) for p in tmp_rules.glob("*"))
        else:
            rules = []
        src_desc = f"特征包 {args.pack}"
    else:
        db = load_db()
        rules = ([str(x) for x in _collect_rule_files(None)]
                 if RULES_DIR.exists() else [])
        src_desc = "本地签名库 + rules/"
    if rules and not scanner.HAS_YARA:
        print("[!] 未安装 yara-python，忽略 YARA 规则")
        rules = []

    ctx = ScanContext(
        rules_paths=rules,
        excludes=list(db.get("exclusions", [])) +
                  list(getattr(args, "exclude", None) or []),
        whitelist=dict(db.get("whitelist", {})),
        vt=False,  # 离线模式：硬性关闭网络信誉查询
        sigcheck=bool(getattr(args, "sigcheck", False)))
    files = ([target] if target.is_file() else
             sorted(p for p in target.rglob("*")
                    if p.is_file() and not _in_quarantine(p)))
    print(f"[i] 离线扫描（不访问网络）: {len(files)} 个文件 · "
          f"特征来源: {src_desc}")

    stats, rows = {"scanned": 0, "detected": 0}, []
    for f in files:
        stats["scanned"] += 1
        for fd in scan_file(f, db, ctx):
            if fd.get("level") == "error":
                print(f"[!] {f}: {fd['name']}")
                continue
            stats["detected"] += 1
            rows.append({"path": str(f), **fd})
            print(f"[x] {f}: [{fd['level'].upper()}] {fd['name']} — "
                  f"{fd.get('detail', '')}")
            if (getattr(args, "quarantine", False)
                    and fd.get("level") == "high"):
                try:
                    print(f"    -> 已隔离: {quarantine_file(f, fd)}")
                except OSError as exc:
                    print(f"[!] 隔离失败: {exc}")

    print(f"\n[i] 离线扫描完成: {stats['scanned']} 个文件, "
          f"{stats['detected']} 条检出（全程未联网）。")
    if getattr(args, "report", None):
        out = report.write_html(args.report, {
            "target": str(target), "files": stats["scanned"],
            "findings": stats["detected"]}, rows)
        print(f"[i] 报告已生成: {out}")
    if tmp_rules:
        shutil.rmtree(tmp_rules, ignore_errors=True)
    return 1 if stats["detected"] else 0


def _collect_rule_files(path=None):
    p = Path(path) if path else RULES_DIR
    if p.is_file():
        return [p]
    if p.is_dir():
        return sorted(list(p.glob("*.yar")) + list(p.glob("*.yara")))
    sys.exit(f"规则路径不存在: {p}")


def cmd_rules(args):
    """rules list / rules check：列出规则或试编译报告错误。"""
    if not scanner.HAS_YARA:
        sys.exit("[!] 未安装 yara-python，无法管理规则"
                 "（python -m pip install yara-python）")
    files = _collect_rule_files(getattr(args, "path", None))
    total, errs = 0, 0
    for f in files:
        try:
            rules = scanner.yara.compile(filepath=str(f))
            names = [r.identifier for r in rules]
        except scanner.yara.Error as exc:
            errs += 1
            print(f"  [FAIL] {f}: {exc}")
            continue
        total += len(names)
        for n in names:
            print(f"  [OK] {f.name}:{n}")
    tail = "，全部编译通过" if not errs else f"，{errs} 个文件编译失败"
    print(f"\n[i] {len(files)} 个规则文件, 共 {total} 条规则{tail}")
    return 1 if errs else 0


def cmd_sig_add(args):
    db = load_db()
    f = Path(args.file)
    if not f.is_file():
        sys.exit(f"文件不存在: {f}")
    _md5, sha = scanner.file_hashes(f)
    if args.whitelist:
        db.setdefault("whitelist", {})[sha] = {
            "name": args.name, "time": time.strftime("%Y-%m-%d %H:%M:%S")}
        save_db(db)
        print(f"[+] 已加入白名单: {args.name} sha256={sha[:16]}...")
    else:
        db.setdefault("hashes", {}).setdefault("sha256", {})[sha] = {
            "name": args.name, "level": args.level}
        save_db(db)
        print(f"[+] 已加入签名库: {args.name} [{args.level}] sha256={sha[:16]}...")
    return 0


def cmd_quar_list(_args):
    from .signatures import QUAR_DIR
    metas = sorted(QUAR_DIR.glob("*.meta.json")) if QUAR_DIR.exists() else []
    if not metas:
        print("[i] 隔离区为空。")
        return 0
    import json
    for m in metas:
        d = json.loads(m.read_text(encoding="utf-8"))
        print(f"{d['name']}  <-  {d['original']}  ({d['finding']} @ {d['time']})")
    return 0


def cmd_quar_restore(args):
    from .scanner import quarantine_restore
    target = quarantine_restore(args.qname)
    print(f"[+] 已恢复到: {target}")
    return 0


def cmd_test(_args):
    from .selftest import run
    return run(load_db())


def _resolve_driver_path(img):
    """把注册表 ImagePath 还原为绝对路径；无法解析返回 None。"""
    import os
    img = img.strip().strip('"')
    low = img.lower()
    sysroot = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    if low.startswith("\\systemroot\\"):
        return sysroot / img[len("\\SystemRoot\\"):]
    if low.startswith("\\??\\"):
        return Path(img[4:])
    if low.startswith("system32\\"):
        return sysroot / img
    p = Path(img)
    return p if p.is_absolute() else None


def cmd_drivers(_args):
    """枚举已注册内核驱动服务并批量体检：签名策略 + BYOVD 黑名单哈希。"""
    import winreg
    from .scanner import file_hashes
    from .wintrust import (HAS_WINTRUST, describe, verify_catalog_batch,
                           verify_embedded)

    db = load_db()
    vuln = db.get("vulnerable_drivers", {})
    stats = {"ok": 0, "unsigned": 0, "fail": 0, "missing": 0, "vuln": 0, "skip": 0}
    rows = []
    total = 0
    pending = []  # (svc, path_str) 无嵌入签名者，待批量 catalog 校验

    try:
        base = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                              r"SYSTEM\CurrentControlSet\Services")
    except OSError as exc:
        sys.exit(f"[!] 无法读取服务注册表: {exc}")
    with base:
        count = winreg.QueryInfoKey(base)[0]
        for i in range(count):
            try:
                svc = winreg.EnumKey(base, i)
                with winreg.OpenKey(base, svc) as k:
                    if (winreg.QueryValueEx(k, "Type")[0] or 0) & 1 != 1:
                        continue  # 仅内核驱动服务 (SERVICE_KERNEL_DRIVER)
                    img = winreg.QueryValueEx(k, "ImagePath")[0]
            except OSError:
                continue
            path = _resolve_driver_path(img)
            if path is None:
                stats["skip"] += 1
                continue
            total += 1
            if not path.is_file():
                stats["missing"] += 1
                rows.append((svc, str(path), "missing", "注册表引用的驱动文件缺失"))
                continue
            try:
                _m, sha = file_hashes(path)
            except OSError:
                stats["skip"] += 1
                continue
            if sha in vuln:
                info = vuln[sha]
                name = info.get("name") if isinstance(info, dict) else str(info)
                stats["vuln"] += 1
                rows.append((svc, str(path), "vuln",
                             f"命中 BYOVD 黑名单: {name or 'Vulnerable-Driver'}"))
                continue
            if not HAS_WINTRUST:
                stats["skip"] += 1
                continue
            try:
                cat, code = verify_embedded(str(path))
            except Exception:
                cat, code = None, None
            if cat == "ok":
                stats["ok"] += 1
            elif cat == "unsigned":
                pending.append((svc, str(path)))
            elif cat == "fail":
                stats["fail"] += 1
                rows.append((svc, str(path), "fail",
                             describe(code) + f" (0x{code:08X})"))
            else:
                stats["skip"] += 1

        # catalog 层批量校验（native 可用时逐个走 native，否则一次 PowerShell 批量）
        if pending:
            try:
                results = verify_catalog_batch([p for _s, p in pending],
                                               driver=True)
            except Exception:
                results = {}
            for svc, pstr in pending:
                cat, code = results.get(pstr, ("unsigned", 0x800B0100))
                stats[cat if cat in ("ok", "unsigned", "fail") else "unsigned"] += 1
                if cat != "ok":
                    rows.append((svc, pstr, cat,
                                 describe(code) + f" (0x{code:08X})"))

    print(f"[i] 系统内核驱动体检: {total} 个驱动")
    print(f"    签名正常 {stats['ok']} | 未签名 {stats['unsigned']} | "
          f"校验失败 {stats['fail']} | 命中黑名单 {stats['vuln']} | "
          f"文件缺失 {stats['missing']} | 跳过 {stats['skip']}")
    for svc, path, kind, note in rows:
        tag = {"vuln": "HIGH", "fail": "HIGH", "unsigned": "MED",
               "missing": "LOW"}.get(kind, "INFO")
        print(f"[x] [{tag}] {svc}  {path}\n      {note}")
    if not rows:
        print("[i] 未发现可疑/异常驱动。")
    return 1 if (stats["vuln"] or stats["fail"]) else 0


def cmd_gui(_args):
    from .gui import main as gui_main
    gui_main()
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="miniantivirus",
        description="miniantivirus 2.0 —— 教学级防御工具："
                    "多引擎扫描 / YARA / 压缩包 / 行为分析 / 准实时监视 / VT 信誉")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="扫描文件或目录")
    sp.add_argument("path")
    sp.add_argument("--rules", help="YARA 规则文件或目录（默认自动加载 rules/）")
    sp.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                    help="fnmatch 排除模式，可多次使用")
    sp.add_argument("--jobs", type=int, default=1, metavar="N",
                    help="并行扫描进程数（默认 1）")
    sp.add_argument("--report", metavar="PATH", help="生成自包含 HTML 报告")
    sp.add_argument("--vt", action="store_true",
                    help="启用 VirusTotal 哈希信誉查询（需 VT_API_KEY）")
    sp.add_argument("--sigcheck", action="store_true",
                    help="校验 PE 数字签名（被篡改/不受信签名报 high）")
    sp.add_argument("--fast", action="store_true",
                    help="增量加速：跳过未变更的清洁文件（签名库/规则更新自动失效）")
    sp.add_argument("--quarantine", action="store_true",
                    help="自动隔离 high 级别检出")
    sp.set_defaults(func=cmd_scan)

    wp = sub.add_parser("watch", help="准实时监视目录并扫描新增/修改文件")
    wp.add_argument("path")
    wp.add_argument("--rules")
    wp.add_argument("--exclude", action="append", default=[], metavar="PATTERN")
    wp.add_argument("--sigcheck", action="store_true", help="校验 PE 数字签名")
    wp.add_argument("--quarantine", action="store_true")
    wp.set_defaults(func=cmd_watch)

    vp = sub.add_parser("vt", help="查询 VirusTotal 哈希信誉（文件或 sha256）")
    vp.add_argument("target", help="文件路径或 64 位 sha256")
    vp.add_argument("--upload", action="store_true",
                    help="上传文件到 VT 多引擎扫描（免费 ≤32MB，公开共享）")
    vp.set_defaults(func=cmd_vt)

    ap = sub.add_parser("analyze", help="样本深度分析：任意文件一键静态体检（绝不执行样本）")
    ap.add_argument("path")
    ap.add_argument("--rules", help="YARA 规则文件或目录（默认自动加载 rules/）")
    ap.add_argument("--vt", action="store_true", help="附加 VirusTotal 信誉查询")
    ap.add_argument("--learn", action="store_true",
                    help="判定恶意时自动提取特征入库（哈希 + 自动 YARA 规则）")
    ap.add_argument("--json", metavar="PATH", help="输出 JSON 报告")
    ap.add_argument("--html", metavar="PATH", help="输出 HTML 报告")
    ap.set_defaults(func=cmd_analyze)

    arp = sub.add_parser("autoruns",
                         help="启动项安全检查（注册表/启动文件夹/计划任务/服务）")
    arp.set_defaults(func=cmd_autoruns)

    prp = sub.add_parser("procs", help="进程安全检查（签名/落位/伪装/黑名单）")
    prp.set_defaults(func=cmd_procs)

    pp = sub.add_parser("protect",
                        help="进程自保护（MiniAVProt 内核驱动，修改状态需管理员）")
    pp.add_argument("--on", action="store_true", help="启用保护")
    pp.add_argument("--off", action="store_true", help="停用保护")
    pp.add_argument("--name", metavar="EXE", help="受保护镜像名（默认 MiniAV.exe）")
    pp.add_argument("--install", action="store_true",
                    help="自动安装并启动驱动（需管理员，GUI 启动时亦自动执行）")
    pp.set_defaults(func=cmd_protect)

    dp = sub.add_parser(
        "defend",
        help="用户态进程自保护：DACL 加固 + 双进程互守护（无需驱动/管理员）")
    dsub = dp.add_subparsers(dest="defendcmd", required=True)
    d1 = dsub.add_parser("start", help="以自保护模式常驻（加固自身 + 派生守护）")
    d1.add_argument("--watch", metavar="DIR",
                    help="常驻时顺带实时监视目录（默认仅驻留）")
    d1.add_argument("--no-dacl", action="store_true",
                    help="跳过 DACL 加固（仅互守护）")
    d1.set_defaults(func=cmd_defend)
    d2 = dsub.add_parser("stop", help="通知自保护常驻正常退出")
    d2.set_defaults(func=cmd_defend)
    d3 = dsub.add_parser("status", help="查看主/守护进程与加固状态")
    d3.set_defaults(func=cmd_defend)
    d4 = dsub.add_parser("__worker", help="内部：守护进程入口（勿手动调用）")
    d4.add_argument("state", nargs="?", default=None)
    d4.set_defaults(func=cmd_defend)

    gd = sub.add_parser("guard", help="自保护：完整性基线与篡改校验")
    gsub = gd.add_subparsers(dest="guardcmd", required=True)
    g1 = gsub.add_parser("baseline", help="生成完整性基线")
    g1.set_defaults(func=cmd_guard)
    g2 = gsub.add_parser("check", help="校验完整性（对比基线）")
    g2.set_defaults(func=cmd_guard)

    kp = sub.add_parser("pack", help="离线特征包管理（export / info）")
    ksub = kp.add_subparsers(dest="packcmd", required=True)
    k1 = ksub.add_parser("export", help="把签名库 + 规则打包成离线特征包")
    k1.add_argument("file", help="输出 zip 路径")
    k1.set_defaults(func=cmd_pack)
    k2 = ksub.add_parser("info", help="查看特征包内容")
    k2.add_argument("file")
    k2.set_defaults(func=cmd_pack)

    op = sub.add_parser("offline", help="离线扫描：全部本地引擎，全程不联网")
    op.add_argument("path")
    op.add_argument("--pack", metavar="ZIP",
                    help="使用离线特征包（默认用本地签名库）")
    op.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                    help="fnmatch 排除模式，可多次使用")
    op.add_argument("--report", metavar="PATH", help="生成 HTML 报告")
    op.add_argument("--sigcheck", action="store_true", help="校验 PE 数字签名")
    op.add_argument("--quarantine", action="store_true", help="自动隔离 high 检出")
    op.set_defaults(func=cmd_offline)

    gp = sub.add_parser("sig-add", help="把文件哈希加入签名库或白名单")
    gp.add_argument("--file", required=True)
    gp.add_argument("--name", required=True)
    gp.add_argument("--level", default="high", choices=["high", "medium", "low"])
    gp.add_argument("--whitelist", action="store_true",
                    help="标记为可信文件（加入白名单而非恶意签名库）")
    gp.set_defaults(func=cmd_sig_add)

    rp = sub.add_parser("rules", help="YARA 规则管理")
    rsub = rp.add_subparsers(dest="rulecmd", required=True)
    r1 = rsub.add_parser("list", help="列出规则文件与规则名")
    r1.add_argument("path", nargs="?", default=None,
                    help="规则文件或目录（默认 rules/）")
    r1.set_defaults(func=cmd_rules)
    r2 = rsub.add_parser("check", help="试编译全部规则并报告错误")
    r2.add_argument("path", nargs="?", default=None)
    r2.set_defaults(func=cmd_rules)

    qp = sub.add_parser("quarantine", help="隔离区管理")
    qsub = qp.add_subparsers(dest="qcmd", required=True)
    q1 = qsub.add_parser("list", help="查看隔离区")
    q1.set_defaults(func=cmd_quar_list)
    q2 = qsub.add_parser("restore", help="恢复隔离文件")
    q2.add_argument("qname")
    q2.set_defaults(func=cmd_quar_restore)

    tp = sub.add_parser("test", help="运行端到端自检")
    tp.set_defaults(func=cmd_test)

    dp = sub.add_parser("drivers", help="系统内核驱动体检（签名 + BYOVD 黑名单）")
    dp.set_defaults(func=cmd_drivers)

    sp = sub.add_parser("sigdb", help="签名库管理（add/addpat/remove/list/stats/import/export）")
    sp.add_argument("rest", nargs=argparse.REMAINDER, help="sigdb 子命令及参数")
    sp.set_defaults(func=cmd_sigdb)

    uip = sub.add_parser("gui", help="启动图形界面")
    uip.set_defaults(func=cmd_gui)
    return p


def cmd_sigdb(args):
    """签名库管理：add/addpat/remove/list/stats/import/export。"""
    from . import sigdb
    from .signatures import save_db

    argv = list(args.rest)
    if not argv:
        print("用法: sigdb <action> [args...]\n"
              "  add <样本文件> [名称] [级别]     从样本文件添加（自动算 md5/sha1/sha256）\n"
              "  addhash <算法> <摘要> <名称> [级别]  手动添加哈希（算法 md5/sha1/sha256）\n"
              "  addpat <regex|hex> <内容> <名称> [级别]  添加模式签名\n"
              "  remove <摘要>                    删除哈希签名\n"
              "  list                             列出全部签名\n"
              "  stats                            签名库统计\n"
              "  import <文件>                    导入 JSON/CSV 签名并合并\n"
              "  export <文件> [json|csv]         导出签名库")
        return 2
    action = argv.pop(0).lower()
    db = load_db()
    try:
        if action == "add":
            if not argv:
                print("[!] 需要样本文件路径")
                return 2
            from pathlib import Path
            sample = Path(argv[0])
            name = argv[1] if len(argv) > 1 else None
            level = argv[2] if len(argv) > 2 else "high"
            hashes, is_new = sigdb.add_sample(db, sample, name, level)
            save_db(db)
            print(("[+] 新增: " if is_new else "[i] 更新: ") +
                  f"{hashes['sha256'][:16]}… 名称={hashes['sha256'] and (argv[1] if len(argv) > 1 else sample.stem)}")
            print("    md5={} sha1={} sha256={}".format(
                hashes["md5"], hashes["sha1"], hashes["sha256"]))
            return 0
        if action == "addhash":
            if len(argv) < 3:
                print("[!] 用法: sigdb addhash <md5|sha1|sha256> <摘要> <名称> [级别]")
                return 2
            algo, digest, is_new = sigdb.add_hash(
                db, argv[1], argv[2], level=argv[3] if len(argv) > 3 else "high",
                algo=argv[0])
            save_db(db)
            print(("[+] 新增" if is_new else "[i] 已存在") + f" {algo} {digest}")
            return 0
        if action == "addpat":
            if len(argv) < 3:
                print("[!] 用法: sigdb addpat <regex|hex> <内容> <名称> [级别]")
                return 2
            is_new = sigdb.add_pattern(
                db, argv[0], argv[1], argv[2],
                level=argv[3] if len(argv) > 3 else "medium")
            save_db(db)
            print(("[+] 新增" if is_new else "[i] 已存在") + " 模式签名")
            return 0
        if action == "remove":
            if not argv:
                print("[!] 需要哈希摘要")
                return 2
            removed = sigdb.remove_hash(db, argv[0])
            save_db(db)
            print(f"[-] 已从 {', '.join(removed)} 段删除")
            return 0
        if action == "list":
            rows = list(sigdb.iter_hashes(db))
            print(f"[i] 哈希签名 {len(rows)} 条:")
            for algo, digest, name, level in rows:
                print(f"  [{level.upper():6s}] {algo:6s} {digest}  {name}")
            for i, sig in enumerate(db.get("patterns", [])):
                print(f"  [{str(sig.get('level', 'medium')).upper():6s}] "
                      f"{sig.get('type', 'regex'):5s} {sig.get('data', '')[:60]}  "
                      f"{sig.get('name', 'Unknown')}  (#{i})")
            return 0
        if action == "stats":
            s = sigdb.stats(db)
            print("[i] 签名库统计:")
            print(f"  哈希签名: md5={s['md5']} sha1={s['sha1']} sha256={s['sha256']}")
            print(f"  模式签名: {s['patterns']}")
            print(f"  白名单: {s['whitelist']}  漏洞驱动黑名单: {s['vulnerable_drivers']}"
                  f"  排除项: {s['exclusions']}")
            return 0
        if action == "import":
            if not argv:
                print("[!] 需要导入文件路径")
                return 2
            added = sigdb.import_file(db, argv[0])
            save_db(db)
            print(f"[+] 导入完成: 新增哈希 {added['hashes']} 条, "
                  f"新增模式 {added['patterns']} 条, 跳过 {added['skipped']} 条")
            return 0
        if action == "export":
            if not argv:
                print("[!] 需要导出文件路径")
                return 2
            fmt = argv[1] if len(argv) > 1 else ("csv" if argv[0].lower().endswith(".csv") else "json")
            n = sigdb.export_file(db, argv[0], fmt)
            print(f"[+] 已导出 {n} 条签名到 {argv[0]} ({fmt})")
            return 0
        print(f"[!] 未知操作: {action}")
        return 2
    except sigdb.SigdbError as exc:
        print(f"[!] {exc}")
        return 1


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[i] 已中断。")
        return 130
