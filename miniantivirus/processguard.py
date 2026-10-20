r"""用户态进程自保护：DACL 加固 + 双进程互守护（无需驱动/管理员，物理机即用）。

背景：Secure Boot 开启时测试签名内核驱动无法加载，MiniAVProt 不可用。
本模块提供纯用户态等价方案：

  1. DACL 加固 —— 对自身进程对象写入 DENY Everyone ACE，剥离外部进程的
     终止/写内存/创建线程/复制句柄/挂起 等权限。普通权限进程（含任务
     管理器）OpenProcess 时直接 ACCESS_DENIED。
     已知局限：持有 SeDebugPrivilege 的提权进程可绕过 DACL 强杀。

  2. 双进程互守护 —— 主进程与守护进程互相监控：
     · 守护进程检测到主进程死亡 → 按记录的命令行重新拉起主进程；
     · 主进程检测到守护进程死亡 → 重新派生守护进程；
     · 新主进程启动后递增代数，旧守护进程发现目标换代后自动退出，
       从机制上避免拉起产生双主进程。
     因此提权强杀主进程后 0.5 秒内会被自动复活。

协调状态（guard_state.json）：{"main_pid", "guard_pid", "gen", "stop",
"restart_cmd", "cwd"}，原子写（tmp.replace）。
"""

import ctypes
import json
import os
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

from .signatures import APP_DIR

STATE_FILE = APP_DIR / "guard_state.json"

# 拒绝给外部进程的权限位（保留 QUERY_/VM_READ 便于观察工具读取信息）
PROCESS_TERMINATE = 0x0001
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

DENY_MASK = (PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION
             | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME)

# security descriptor 常量
SE_KERNEL_OBJECT = 6
DACL_SECURITY_INFORMATION = 0x4
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
GRANT_ACCESS = 1
DENY_ACCESS = 3
TRUSTEE_IS_SID = 0
TRUSTEE_IS_WELL_KNOWN_GROUP = 5
WORLD_SID = "S-1-1-0"          # Everyone

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_adv = ctypes.WinDLL("advapi32", use_last_error=True)

_k32.OpenProcess.restype = ctypes.c_void_p
_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.GetCurrentProcessId.restype = wintypes.DWORD


class _Trustee(ctypes.Structure):
    _fields_ = [("pMultipleTrustee", ctypes.c_void_p),
                ("MultipleTrusteeOperation", ctypes.c_int),
                ("TrusteeForm", ctypes.c_int),
                ("TrusteeType", ctypes.c_int),
                ("ptstrName", ctypes.c_void_p)]


class _ExplicitAccess(ctypes.Structure):
    _fields_ = [("grfAccessPermissions", wintypes.DWORD),
                ("grfAccessMode", ctypes.c_int),
                ("grfInheritance", wintypes.DWORD),
                ("Trustee", _Trustee)]


_adv.GetSecurityInfo.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.c_void_p]
_adv.GetSecurityInfo.restype = wintypes.DWORD
_adv.SetSecurityInfo.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.c_void_p, ctypes.c_void_p]
_adv.SetSecurityInfo.restype = wintypes.DWORD
_adv.SetEntriesInAclW.argtypes = [wintypes.ULONG, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_void_p]
_adv.SetEntriesInAclW.restype = wintypes.DWORD
_adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
_adv.ConvertStringSidToSidW.restype = wintypes.BOOL
_k32.LocalFree.argtypes = [wintypes.HLOCAL]
_k32.LocalFree.restype = wintypes.HLOCAL
_k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
_k32.GetExitCodeProcess.restype = wintypes.BOOL

STILL_ACTIVE = 259

# 进程打开自身时的真句柄（DACL 加固后仍保持打开时的权限，用于恢复）
_self_handle = None


class GuardError(Exception):
    """用户态自保护操作失败（用户可读消息）。"""


def _open_self():
    """打开当前进程真句柄（PROCESS_ALL_ACCESS），缓存复用。"""
    global _self_handle
    if _self_handle is None:
        ctypes.set_last_error(0)
        h = _k32.OpenProcess(0x1FFFFF, False, _k32.GetCurrentProcessId())
        if not h:
            raise GuardError(
                f"打开自身进程失败 (WinError {ctypes.get_last_error()})")
        _self_handle = h
    return _self_handle


def _world_sid():
    sid = ctypes.c_void_p()
    if not _adv.ConvertStringSidToSidW(WORLD_SID, ctypes.byref(sid)):
        raise GuardError(
            f"解析 Everyone SID 失败 (WinError {ctypes.get_last_error()})")
    return sid


def _make_access(mode, mask, sid):
    ea = _ExplicitAccess()
    ea.grfAccessPermissions = mask
    ea.grfAccessMode = mode
    ea.grfInheritance = 0
    ea.Trustee.pMultipleTrustee = None
    ea.Trustee.MultipleTrusteeOperation = 0
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP
    ea.Trustee.ptstrName = sid
    return ea


def harden_self(mask=DENY_MASK):
    """对当前进程写入 DENY Everyone DACL（普通权限外部进程无法终止/改写）。"""
    h = _open_self()
    sid = _world_sid()
    sd = ctypes.c_void_p()
    old_dacl = ctypes.c_void_p()
    rc = _adv.GetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                              None, None, ctypes.byref(old_dacl), None,
                              ctypes.byref(sd))
    if rc != 0:
        raise GuardError(f"读取进程 DACL 失败 (0x{rc:08X})")
    try:
        ea = _make_access(DENY_ACCESS, mask, sid)
        new_dacl = ctypes.c_void_p()
        rc = _adv.SetEntriesInAclW(1, ctypes.byref(ea), old_dacl,
                                   ctypes.byref(new_dacl))
        if rc != 0:
            raise GuardError(f"构造 DACL 失败 (0x{rc:08X})")
        try:
            rc = _adv.SetSecurityInfo(h, SE_KERNEL_OBJECT,
                                      DACL_SECURITY_INFORMATION,
                                      None, None, new_dacl, None)
            if rc != 0:
                raise GuardError(f"写入进程 DACL 失败 (0x{rc:08X})")
        finally:
            _k32.LocalFree(new_dacl)
    finally:
        _k32.LocalFree(sd)


def restore_self():
    """恢复为默认可访问 DACL（ALLOW Everyone，用于正常退出前解除加固）。"""
    h = _open_self()
    sid = _world_sid()
    ea = _make_access(GRANT_ACCESS, 0x1FFFFF, sid)  # GENERIC_ALL
    new_dacl = ctypes.c_void_p()
    rc = _adv.SetEntriesInAclW(1, ctypes.byref(ea), None, ctypes.byref(new_dacl))
    if rc != 0:
        raise GuardError(f"构造恢复 DACL 失败 (0x{rc:08X})")
    try:
        rc = _adv.SetSecurityInfo(h, SE_KERNEL_OBJECT,
                                  DACL_SECURITY_INFORMATION
                                  | PROTECTED_DACL_SECURITY_INFORMATION,
                                  None, None, new_dacl, None)
        if rc != 0:
            raise GuardError(f"恢复进程 DACL 失败 (0x{rc:08X})")
    finally:
        _k32.LocalFree(new_dacl)


def is_hardened(pid):
    """探测目标进程是否对外部不可终止（True/False；None=无法判定）。

    注意：探测者持有已启用的 SeDebugPrivilege 时会被内核放行，永远 False。
    """
    ctypes.set_last_error(0)
    h = _k32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
    if h:
        _k32.CloseHandle(h)
        return False
    err = ctypes.get_last_error()
    if err == 5:
        return True
    return None


def pid_alive(pid):
    """检测进程是否存活（仅查询权限，不触发 DACL 拒绝）。

    注意：进程对象在所有句柄关闭前不销毁，OpenProcess 对已终止进程
    仍可能成功，因此必须用 GetExitCodeProcess 判断是否 STILL_ACTIVE。
    """
    ctypes.set_last_error(0)
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not h:
        return False
    code = wintypes.DWORD()
    ok = _k32.GetExitCodeProcess(h, ctypes.byref(code))
    _k32.CloseHandle(h)
    return bool(ok) and code.value == STILL_ACTIVE


def read_state(path=None):
    try:
        return json.loads(Path(path or STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def write_state(st, path=None):
    p = Path(path or STATE_FILE)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    tmp.replace(p)


def restart_command():
    """重建当前主进程的启动命令行（守护进程拉起新实例时用）。"""
    if getattr(sys, "frozen", False):
        return [sys.executable] + list(sys.argv[1:])
    return [sys.executable, "-m", "miniantivirus"] + list(sys.argv[1:])


def spawn_worker(state_path=None):
    """派生隐藏窗口的守护进程（独立于主进程生命周期）。

    标志仅用 CREATE_NO_WINDOW（与 DETACHED_PROCESS 互斥，不可并用），
    标准 IO 全部重定向 DEVNULL。
    """
    if getattr(sys, "frozen", False):
        cmd = [sys.executable, "defend", "__worker"]
    else:
        cmd = [sys.executable, "-m", "miniantivirus", "defend", "__worker"]
    if state_path:
        cmd += [str(state_path)]
    return subprocess.Popen(
        cmd, creationflags=subprocess.CREATE_NO_WINDOW,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, cwd=str(APP_DIR))


def worker_loop(state_path=None):
    """守护进程主循环：监视主进程，死亡即拉起新实例。

    退出条件：stop 标记 / 状态文件丢失 / 目标换代（新一代主进程接管）/
    拉起完成。守护自身也被 DACL 加固，普通权限无法被杀。
    """
    st = read_state(state_path)
    if not st or not st.get("main_pid"):
        return
    target = int(st["main_pid"])
    path = state_path or STATE_FILE
    while True:
        st = read_state(path)
        if not st or st.get("stop"):
            return
        if int(st.get("main_pid", -1)) != target:
            return  # 新一代主进程已接管，本守护退役
        if not pid_alive(target):
            cmd = st.get("restart_cmd") or []
            if cmd:
                try:
                    subprocess.Popen(
                        cmd, creationflags=subprocess.CREATE_NO_WINDOW,
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        cwd=st.get("cwd") or str(APP_DIR))
                except OSError:
                    pass
            return  # 拉起新主进程后退役（新主进程自会派生新守护）
        time.sleep(0.5)


def run_daemonized(watch_dir=None, use_dacl=True, state_path=None):
    """主进程自保护常驻入口：加固自身 → 派生守护 → 进入服务循环。

    watch_dir 非空时顺带对该目录做实时监视（复用 watcher），
    否则仅驻留心跳。返回退出码。
    """
    path = state_path or STATE_FILE
    if use_dacl:
        try:
            harden_self()
        except GuardError as exc:
            print(f"[!] DACL 加固失败（继续仅互守护模式）: {exc}")
            use_dacl = False
        else:
            print(f"[+] 进程 DACL 已加固: 拒绝 Everyone "
                  f"终止/写内存/创建线程/复制句柄/挂起 (0x{DENY_MASK:04X})")

    old = read_state(path) or {}
    st = {"main_pid": os.getpid(),
          "guard_pid": None,
          "gen": int(old.get("gen", 0)) + 1,
          "stop": False,
          "hardened": bool(use_dacl),
          "watch_dir": str(watch_dir) if watch_dir else "",
          "restart_cmd": restart_command(),
          "cwd": os.getcwd()}
    write_state(st, path)

    proc = spawn_worker(state_path if state_path else None)
    st["guard_pid"] = proc.pid
    write_state(st, path)
    print(f"[+] 守护进程已派生: PID {proc.pid} · 状态文件: {path}")
    print(f"[i] 主进程 PID {st['main_pid']} · 代数 {st['gen']}"
          f"{' · DACL 加固' if use_dacl else ''}")
    print("[i] 互守护已建立：强杀本进程将被 0.5s 内自动复活；"
          "正常退出请用 `defend stop`。按 Ctrl+C 也可正常退出。")

    stop_event = threading.Event()
    watch_thread = None
    if watch_dir:
        from .signatures import load_db
        from . import watcher
        db = load_db()
        ctx = _build_ctx(db)
        watch_thread = threading.Thread(
            target=_watch_safe,
            args=(watch_dir, db, ctx, stop_event), daemon=True)
        watch_thread.start()
        print(f"[i] 实时监视已启动: {watch_dir}")

    try:
        while not stop_event.is_set():
            cur = read_state(path) or {}
            if cur.get("stop"):
                break
            if not (proc.pid and pid_alive(proc.pid)):  # 守护死亡 → 重派生
                proc = spawn_worker(state_path if state_path else None)
                st["guard_pid"] = proc.pid
                write_state(st, path)
                print(f"[+] 守护进程重启: PID {proc.pid}")
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[i] 收到退出信号")
    finally:
        st["stop"] = True
        write_state(st, path)
        if use_dacl:
            try:
                restore_self()
            except GuardError:
                pass
        print("[i] 自保护常驻已退出")
    return 0


def _build_ctx(db):
    """构造默认扫描上下文（自动加载 rules/，与 watch 命令一致）。"""
    from .scanner import ScanContext, HAS_YARA
    from .signatures import RULES_DIR
    rules = []
    if HAS_YARA and RULES_DIR.exists():
        rules = sorted(str(x) for x in
                       list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara")))
    return ScanContext(rules_paths=rules,
                       whitelist=dict(db.get("whitelist", {})))


def _watch_safe(watch_dir, db, ctx, stop_event):
    from . import watcher
    try:
        watcher.watch(watch_dir, db, ctx, stop_event=stop_event)
    except Exception as exc:  # 守护常驻不允许监视异常拖垮进程
        print(f"[!] 实时监视异常: {exc}")


def guard_stop(state_path=None):
    """通知自保护常驻退出（写入 stop 标记，等待主进程与守护退役）。"""
    path = state_path or STATE_FILE
    st = read_state(path)
    if not st or not st.get("main_pid"):
        print("[i] 未发现自保护常驻状态（本就未运行）。")
        return 0
    main_pid = int(st["main_pid"])
    st["stop"] = True
    write_state(st, path)
    print(f"[i] 已发送停止信号 (主进程 {main_pid})")
    for _ in range(10):
        if not pid_alive(main_pid):
            print("[+] 自保护常驻已正常退出。")
            try:
                Path(path).unlink()
            except OSError:
                pass
            return 0
        time.sleep(0.5)
    print(f"[!] 主进程 {main_pid} 未在 5 秒内退出"
          f"{'（DACL 已加固，需提权强杀后由守护复活）' if st.get('hardened') else ''}")
    return 1


def guard_status(state_path=None):
    """报告自保护状态：主/守护进程 PID、存活、加固状态、代数。"""
    path = state_path or STATE_FILE
    st = read_state(path)
    if not st or not st.get("main_pid"):
        print("[i] 自保护未运行（无状态文件）。")
        print("[i] 启动: python -m miniantivirus defend start [--watch 目录]")
        return 0
    main_pid = int(st["main_pid"])
    guard_pid = st.get("guard_pid")
    alive = pid_alive(main_pid)
    hardened = None
    if alive:
        hardened = is_hardened(main_pid)
    state = "运行中" if alive else "已退出"
    if alive and hardened:
        state += " · DACL 已加固（外部不可终止）"
    elif alive:
        state += " · DACL 未加固/不可判定"
    print(f"主进程: PID {main_pid} · {state} · 代数 {st.get('gen', '?')}")
    if guard_pid:
        print(f"守护进程: PID {guard_pid} · "
              f"{'运行中' if pid_alive(int(guard_pid)) else '已退出'}")
    print(f"监视目录: {st.get('watch_dir') or '-'}")
    print(f"状态文件: {path}")
    return 0 if alive else 1
