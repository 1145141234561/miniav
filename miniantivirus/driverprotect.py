r"""进程自保护驱动接口：与 MiniAVProt 内核驱动通信。

驱动通过 ObRegisterCallbacks 拦截对受保护镜像（默认 MiniAV.exe）进程的
句柄打开/复制，剥离 终止/写内存/创建线程/挂起 等危险权限，
使用户态恶意软件无法杀死或篡改 MiniAV 进程（内核级自保护）。

控制设备 \\.\MiniAVProt 的 DACL 仅允许 SYSTEM/管理员读写；
驱动未加载或权限不足时接口优雅降级（safe_status 永不抛异常）。
"""

import ctypes
import struct
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

DEVICE = r"\\.\MiniAVProt"

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE = ctypes.c_void_p(-1).value

LOAD_HINT = (
    "安装/启动（管理员）:\n"
    "  1. bcdedit /set testsigning on  （重启生效）\n"
    "  2. 关闭 内核隔离-内存完整性（HVCI 会阻止测试签名驱动）\n"
    "  3. signtool sign /fd sha256 /a driver\\MiniAVProt.sys\n"
    "  4. sc create MiniAVProt type= kernel binPath= <MiniAVProt.sys 路径>\n"
    "  5. sc start MiniAVProt")


def _ctl_code(device, function, method=0, access=0):
    return (device << 16) | (access << 14) | (function << 2) | method


IOCTL_SET_NAME = _ctl_code(0x22, 0x800)   # 输入 CHAR[16] 受保护镜像名
IOCTL_ENABLE = _ctl_code(0x22, 0x801)     # 输入 ULONG 1/0
IOCTL_STATUS = _ctl_code(0x22, 0x802)     # 输出 {ULONG;ULONG;CHAR[16]}


class DriverError(Exception):
    """驱动通信失败（未加载/参数无效等）。"""


class _Status(ctypes.Structure):
    _fields_ = [("enabled", ctypes.c_uint32),
                ("mask", ctypes.c_uint32),
                ("name", ctypes.c_char * 16)]


_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateFileW.restype = ctypes.c_void_p
_k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                             ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                             ctypes.c_void_p]
_k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                 ctypes.c_void_p, wintypes.DWORD,
                                 ctypes.c_void_p, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
_k32.DeviceIoControl.restype = wintypes.BOOL
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.CloseHandle.restype = wintypes.BOOL


def _open(write):
    """打开控制设备；write=True 需要 GENERIC_WRITE（仅管理员可获授权）。"""
    access = (GENERIC_READ | GENERIC_WRITE) if write else 0
    ctypes.set_last_error(0)
    h = _k32.CreateFileW(DEVICE, access, 0, None, OPEN_EXISTING, 0, None)
    if h in (None, INVALID_HANDLE):
        err = ctypes.get_last_error()
        if err in (2, 3):
            raise DriverError("自保护驱动未加载（\\Device\\MiniAVProt 不存在）")
        if err == 5:
            raise PermissionError("访问控制设备被拒绝（需要管理员权限）")
        raise DriverError(f"打开控制设备失败 (WinError {err})")
    return h


def _ioctl(h, code, inbuf=None, outbuf=None):
    n = wintypes.DWORD(0)
    ok = _k32.DeviceIoControl(
        h, code, inbuf, len(inbuf) if inbuf else 0,
        outbuf, len(outbuf) if outbuf else 0, ctypes.byref(n), None)
    if not ok:
        err = ctypes.get_last_error()
        raise DriverError(f"DeviceIoControl 失败 (WinError {err})")
    return n.value


def set_name(name):
    """设置受保护镜像名（仅 [A-Za-z0-9._-]，≤15 字符；需管理员）。"""
    if not name or len(name.encode()) > 15 or any(
            not (c.isalnum() and c.isascii()) and c not in "._-" for c in name):
        raise DriverError("镜像名仅允许 1-15 个 [A-Za-z0-9._-] 字符")
    h = _open(write=True)
    try:
        _ioctl(h, IOCTL_SET_NAME, name.encode() + b"\x00")
    finally:
        _k32.CloseHandle(h)


def enable(on):
    """启用/停用进程保护（需管理员）。"""
    h = _open(write=True)
    try:
        _ioctl(h, IOCTL_ENABLE, struct.pack("<I", 1 if on else 0))
    finally:
        _k32.CloseHandle(h)


def safe_status():
    """查询驱动状态。返回 (dict|None, 错误说明|None)，不抛异常。"""
    try:
        h = _open(write=False)
    except DriverError as exc:
        return None, str(exc)
    except PermissionError as exc:
        return None, str(exc)
    try:
        st = _Status()
        _ioctl(h, IOCTL_STATUS, outbuf=st)
        return {"enabled": bool(st.enabled), "mask": st.mask,
                "name": st.name.decode("ascii", "ignore").rstrip("\x00")}, None
    except DriverError as exc:
        return None, str(exc)
    finally:
        _k32.CloseHandle(h)


def format_report(d):
    state = "已启用" if d["enabled"] else "已停用"
    return (f"[i] 进程自保护驱动: {state}\n"
            f"    保护对象: {d['name']} · 剥离权限掩码: 0x{d['mask']:04X}\n"
            f"    （终止/写内存/创建线程/挂起 等权限对外部进程已剥离）")


def _is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def default_sys_path():
    """MiniAVProt.sys 的默认查找位置：打包后同目录 / 源码 driver/ 目录。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / "MiniAVProt.sys"
    from .signatures import APP_DIR
    return APP_DIR / "driver" / "MiniAVProt.sys"


_START_ERRORS = {
    5: "拒绝访问（需要管理员权限）",
    577: "驱动签名校验失败（未签名或测试签名模式未开启）",
    1058: "MiniAVProt 服务被禁用（sc config MiniAVProt start= demand）",
    1072: "服务正标记为删除，请重启后再试",
    1275: "驱动被系统策略阻止（如 HVCI/内核隔离开启）",
}


def ensure_loaded(sys_path=None):
    """启动即自动加载：未安装则安装服务，未启动则启动，随后查询状态。

    返回 (状态 dict|None, 错误说明|None)，不抛异常。
    """
    d, err = safe_status()
    if d is not None:
        return d, None
    if not _is_admin():
        return None, "需要管理员权限才能自动加载驱动"
    if sys_path is None:
        sys_path = default_sys_path()
    if not sys_path or not Path(sys_path).is_file():
        return None, f"未找到驱动文件 MiniAVProt.sys（期望位置: {sys_path or '-'}）"

    def sc(*args):
        return subprocess.run(["sc", *args], capture_output=True,
                              creationflags=subprocess.CREATE_NO_WINDOW
                              ).returncode

    if sc("query", "MiniAVProt") == 1060:  # 服务不存在 → 安装
        rc = sc("create", "MiniAVProt", "type=", "kernel",
                "binPath=", str(Path(sys_path).resolve()), "start=", "demand")
        if rc not in (0, 1073):  # 1073=已存在（并发场景）
            return None, f"sc create 失败 (rc={rc})"
    rc = sc("start", "MiniAVProt")
    if rc != 0:
        return None, _START_ERRORS.get(rc, f"sc start 失败 (rc={rc})")
    for _ in range(10):  # 等设备对象出现（最多 2 秒）
        d, err = safe_status()
        if d is not None:
            return d, None
        time.sleep(0.2)
    return None, f"驱动已启动但控制设备未响应: {err}"
