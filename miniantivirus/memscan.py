"""活进程内存扫描——针对"内存注入/无文件攻击"的动态检测层。

无文件攻击的载荷只存在于活进程内存（磁盘无文件可扫），唯一检测落点
是读取运行中进程的内存。本模块为纯只读防御：OpenProcess(VM_READ) +
VirtualQueryEx 走区 + ReadProcessMemory 取内容，交给既有规则引擎
（YARA/模式/行为正则）复扫——不注入、不写入、不终止任何进程。

检测面（按置信度）：
- 无回退执行区（MEM_PRIVATE + PAGE_EXECUTE_*）：注入 shellcode 的
  经典栖身之所——文件映射区必有 Type=MEM_IMAGE，私有可执行即无文件
- shellcode 前导字节：MSF x64 {FC 48 83 E4 F0} / CS {FC E8 89 00 00 00}
- 内存 YARA/模式/行为标记：注入内容直接撞既有规则库
- PEB 摘链模块（孤儿镜像区）：Type=MEM_IMAGE 但不在模块列表
- 进程空心化：主模块内存 PE 头被抹除/与磁盘文件不一致

预算控制：单区读取 ≤8MB、单进程 ≤64 区 / 64MB、全机 ≤512MB；
权限不足（受保护/高完整性进程）计入 denied 并跳过。默认跳过自身
进程（扫描器自带恶意规则字符串，扫自己必然自命中）。
"""

import ctypes
import os
from ctypes import wintypes
from pathlib import Path

from .scanner import content_findings

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
PAGE_EXECUTE_SET = frozenset({0x10, 0x20, 0x40, 0x80})

MAX_REGION_READ = 8 * 1024 * 1024       # 单区读取上限
MAX_PROC_REGIONS = 64                   # 单进程扫描区数上限
MAX_PROC_BYTES = 64 * 1024 * 1024       # 单进程字节预算
MAX_TOTAL_BYTES = 512 * 1024 * 1024     # 全机字节预算
MIN_TEXT_REGION = 64                    # 文本扫描最小区尺寸

# MSF/CS x64 shellcode 前导（仅对无回退执行区报 high，压制镜像区误报）
_SHELLCODE_PROLOGUES = (b"\xfc\x48\x83\xe4\xf0",      # cld; and rsp,-0x10
                        b"\xfc\xe8\x89\x00\x00\x00")  # cld; call $+0x8e

# 无回退执行区内的行为标记（复用解混淆引擎的标记表）
from .deobf import _EXEC_MARKERS_LC

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)


class _MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("_pad1", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("_pad2", wintypes.DWORD)]


def _enable_debug_privilege():
    """尽力启用 SeDebugPrivilege（读高完整性进程内存），失败静默。"""
    try:
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        tok = wintypes.HANDLE()
        if not adv.OpenProcessToken(ctypes.WinDLL("kernel32").GetCurrentProcess(),
                                    0x0028, ctypes.byref(tok)):
            return
        class _TP(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Luid", wintypes.LUID), ("Attributes", wintypes.DWORD)]
        tp = _TP(1)
        if adv.LookupPrivilegeValueW(None, "SeDebugPrivilege",
                                     ctypes.byref(tp.Luid)):
            tp.Attributes = 2  # SE_PRIVILEGE_ENABLED
            adv.AdjustTokenPrivileges(tok, False, ctypes.byref(tp),
                                      0, None, None)
        ctypes.WinDLL("kernel32").CloseHandle(tok)
    except Exception:
        pass


def _iter_regions(h):
    """yield (base, size, state, protect, type)。"""
    addr = 0
    mbi = _MBI()
    while addr < 0x7FFFFFFEFFFF:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr),
                                  ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        size = mbi.RegionSize
        if not size:
            break
        yield (mbi.BaseAddress or addr, size, mbi.State, mbi.Protect, mbi.Type)
        addr += size


def _read_mem(h, base, size):
    """读取一段内存（带单区上限），失败返回 b""。"""
    size = min(size, MAX_REGION_READ)
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size,
                                 ctypes.byref(got)):
        return b""
    return buf.raw[:got.value]


def _proc_modules(h):
    """返回 ({模块基址: 路径}, 主模块基址)。"""
    need = wintypes.DWORD()
    LIST_MODULES_ALL = 0x03
    if not psapi.EnumProcessModulesEx(h, None, 0, ctypes.byref(need),
                                      LIST_MODULES_ALL):
        return {}, 0
    count = need.value // ctypes.sizeof(wintypes.HMODULE)
    if not count or count > 4096:
        return {}, 0
    arr = (wintypes.HMODULE * count)()
    if not psapi.EnumProcessModulesEx(h, ctypes.byref(arr),
                                      ctypes.sizeof(arr),
                                      ctypes.byref(need), LIST_MODULES_ALL):
        return {}, 0
    buf = ctypes.create_unicode_buffer(1024)
    mods = {}
    main = 0
    for i, m in enumerate(arr[:count]):
        n = wintypes.DWORD(1024)
        if psapi.GetModuleFileNameExW(h, m, buf, ctypes.byref(n)):
            mods[m] = buf.value
            if i == 0:
                main = m
    return mods, main


def _check_hollow(mem, disk):
    """主模块内存头 vs 磁盘头校验（纯函数，供单测复用）。

    返回 None 或 (level, detail)：头被抹除 → high；关键字段
    （TimeDateStamp/SizeOfImage）与磁盘不一致 → medium（hollowing/篡改）。
    """
    if len(mem) < 0x40 or mem[0:2] != b"MZ":
        return ("high", "主模块内存 PE 头被抹除/破坏（头劫持/注入痕迹）")
    off = int.from_bytes(mem[0x3C:0x40], "little")
    if not (0x40 <= off <= len(mem) - 4) or mem[off:off + 4] != b"PE\x00\x00":
        return ("high", "主模块内存 PE 签名缺失/重定向非法（头劫持痕迹）")
    if len(mem) >= off + 12 and len(disk) >= off + 12:
        if mem[off + 8:off + 12] != disk[off + 8:off + 12]:
            return ("medium", "主模块内存 TimeDateStamp 与磁盘文件不一致"
                              "（疑似 hollowing/换体篡改，需人工研判）")
    return None


def _scan_region_content(h, base, size, db, ctx, budget):
    """扫描一个无回退执行区，返回 findings 列表（内部逐步扣预算）。"""
    if budget["proc_bytes"] <= 0 or budget["total_bytes"] <= 0:
        return []
    data = _read_mem(h, base, size)
    budget["proc_bytes"] -= len(data)
    budget["total_bytes"] -= len(data)
    if not data:
        return []
    out = []
    # 1) 内存 YARA/模式/EICAR 复扫
    for fd in content_findings(data, db, ctx):
        if fd.get("level") == "error":
            continue
        out.append({**fd,
                    "detail": f"无回退执行区({hex(base)})检出: {fd.get('detail', '')}"})
    # 2) shellcode 前导
    for pl in _SHELLCODE_PROLOGUES:
        if data.count(pl):
            out.append({"name": "MEM-Injected-Shellcode", "level": "high",
                        "detail": f"无回退执行区({hex(base)})含 MSF/CS x64 "
                                  f"shellcode 前导 {pl.hex()}（内存注入痕迹）"})
            break
    # 3) 行为标记明文
    low = data.lower()
    marks = [m for m in _EXEC_MARKERS_LC if m in low]
    if marks:
        out.append({"name": "MEM-Exec-Marker", "level": "medium",
                    "detail": f"无回退执行区({hex(base)})含行为标记明文: "
                              + ", ".join(m.decode() for m in marks[:3])})
    return out


def _scan_private_text(h, base, size, budget):
    """私有 RW 数据区的文本行为扫描（weight≥2 才报，压制堆噪声）。"""
    from . import sandbox as _sandbox
    if (size < MIN_TEXT_REGION or size > MAX_REGION_READ
            or budget["proc_bytes"] <= 0 or budget["total_bytes"] <= 0):
        return []
    data = _read_mem(h, base, size)
    budget["proc_bytes"] -= len(data)
    budget["total_bytes"] -= len(data)
    if not data:
        return []
    out, seen = [], set()
    for text in (data.decode("utf-8", "ignore"),
                 data.decode("utf-16-le", "ignore")):
        for hh in _sandbox.text_hits(text):
            if hh["weight"] < 2 or hh["name"] in seen:
                continue
            seen.add(hh["name"])
            out.append({"name": f"MEM-{hh['name']}", "level": "medium",
                        "detail": f"进程内存数据区({hex(base)})命中行为特征: "
                                  f"{hh['desc']}"})
        if len(out) >= 3:
            break
    return out


def scan_processes(db, ctx, pids=None, include_self=False):
    """活进程内存扫描，返回 (rows, stats)。

    rows: [{pid, proc, path, name, level, region, detail}]
    pids 指定时只扫这些进程；include_self 控制是否包含本进程
    （默认跳过——扫描器规则库字符串会自命中）。
    """
    _enable_debug_privilege()
    from .procscan import _list_processes
    procs = dict(_list_processes())
    if pids:
        procs = {pid: procs.get(pid, f"<pid:{pid}>") for pid in pids}
    self_pid = os.getpid()
    if not include_self:
        procs.pop(self_pid, None)

    rows = []
    budget = {"total_bytes": MAX_TOTAL_BYTES}
    stats = {"total": len(procs), "scanned": 0, "denied": 0,
             "regions": 0, "mb": 0.0, "findings": 0, "suspicious": 0}

    for pid, path in procs.items():
        if budget["total_bytes"] <= 0:
            break
        h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                            False, pid)
        if not h:
            h = k32.OpenProcess(PROCESS_VM_READ, False, pid)
        if not h:
            stats["denied"] += 1
            continue
        try:
            if not path.startswith("<pid"):
                pname = Path(path).name
            else:
                buf = ctypes.create_unicode_buffer(1024)
                n = wintypes.DWORD(1024)
                pname = (buf.value if k32.QueryFullProcessImageNameW(
                    h, 0, buf, ctypes.byref(n)) else f"pid:{pid}")
            budget["proc_bytes"] = MAX_PROC_BYTES
            proc_fds = []
            mods, main = {}, 0
            try:
                mods, main = _proc_modules(h)
            except Exception:
                pass
            n_scanned = 0
            # 两遍扫描：先无回退执行区/孤儿镜像（注入检测优先），
            # 再用剩余配额扫堆文本层——防止海量堆区耗尽配额漏检注入
            committed = [(b, sz, p, t) for b, sz, st, p, t in _iter_regions(h)
                         if st == MEM_COMMIT]
            hot = [(b, sz, p, t) for b, sz, p, t in committed
                   if (t == MEM_PRIVATE and p in PAGE_EXECUTE_SET)
                   or (t == MEM_IMAGE and p in PAGE_EXECUTE_SET
                       and b not in mods)]
            for base, size, protect, rtype in hot:
                if n_scanned >= MAX_PROC_REGIONS:
                    break
                n_scanned += 1
                stats["regions"] += 1
                if rtype == MEM_PRIVATE:
                    for fd in _scan_region_content(h, base, size, db, ctx,
                                                   budget):
                        proc_fds.append({**fd, "region": hex(base)})
                else:  # 孤儿镜像区：PEB 摘链/手动映射痕迹
                    proc_fds.append({
                        "name": "MEM-Orphan-Image", "level": "medium",
                        "region": hex(base),
                        "detail": f"镜像区({hex(base)})不在模块列表"
                                  "（PEB 摘链/手动映射痕迹）"})
            for base, size, protect, rtype in committed:
                if (n_scanned >= MAX_PROC_REGIONS
                        or budget["proc_bytes"] <= 0):
                    break
                if rtype == MEM_PRIVATE and protect == 0x04:
                    txt = _scan_private_text(h, base, size, budget)
                    if txt:
                        n_scanned += 1
                        proc_fds.extend(txt)
                        stats["regions"] += 1
            # 空心化校验：主模块内存头 vs 磁盘
            if main and len(main_path := mods.get(main, "")) > 3:
                mem_head = _read_mem(h, main, 0x400)
                try:
                    disk_head = Path(main_path).read_bytes()[:0x400]
                    res = _check_hollow(mem_head, disk_head)
                except OSError:
                    res = None
                if res:
                    proc_fds.append({"name": f"MEM-{('Header-Stomped' if res[0] == 'high' else 'Module-Tampered')}",
                                     "level": res[0], "region": hex(main),
                                     "detail": res[1]})
            if proc_fds:
                for fd in proc_fds:
                    rows.append({"pid": pid, "proc": pname, "path": path,
                                 "name": fd["name"], "level": fd["level"],
                                 "region": fd.get("region", "-"),
                                 "detail": fd.get("detail", "")})
                if any(fd["level"] in ("high", "medium") for fd in proc_fds):
                    stats["suspicious"] += 1
            stats["scanned"] += 1
            stats["mb"] += round((MAX_PROC_BYTES - budget["proc_bytes"])
                                 / 1048576, 1)
        finally:
            k32.CloseHandle(h)

    stats["findings"] = len(rows)
    return rows, stats


def format_report(rows, stats):
    L = [f"进程内存扫描（无文件攻击检测）: 打开 {stats['scanned']} · "
         f"拒绝 {stats['denied']} · 扫描区 {stats['regions']} · "
         f"读取 {stats['mb']:.1f}MB"]
    L.append(f"    检出 {stats['findings']} 条 · 可疑进程 {stats['suspicious']}")
    for r in rows:
        L.append(f"  [{r['level'].upper()}] PID {r['pid']} {r['proc']} "
                 f"@ {r['region']}")
        L.append(f"      {r['name']}: {r['detail']}")
    if not rows:
        L.append("[i] 未发现内存注入/无文件攻击痕迹。")
    return "\n".join(L)
