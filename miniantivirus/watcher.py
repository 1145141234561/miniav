"""准实时监视：watchdog 观察文件系统事件，0.25s 去抖后扫描新增/修改的文件。"""

import threading
import time
from pathlib import Path

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

DEBOUNCE = 0.25  # 编辑器/程序写文件往往触发多次事件，去抖后只扫最后一次

if HAS_WATCHDOG:
    class _Handler(FileSystemEventHandler):
        def __init__(self, on_event):
            self.on_event = on_event

        def on_created(self, event):
            if not event.is_directory:
                self.on_event(event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                self.on_event(event.src_path)

        def on_moved(self, event):
            if not event.is_directory:
                self.on_event(event.dest_path)
else:
    _Handler = None


def watch(path, db, ctx=None, quarantine=False, stop_event=None, on_result=None,
          quiet=False):
    """阻塞式监视目录（recursive）。stop_event 置位或 Ctrl+C 后返回统计 dict。"""
    if not HAS_WATCHDOG:
        raise RuntimeError("实时监视需要 watchdog 库: python -m pip install watchdog")

    from .scanner import _in_quarantine, quarantine_file, scan_file

    root = Path(path).resolve()
    stats = {"scanned": 0, "findings": 0, "quarantined": 0}
    stop = stop_event or threading.Event()
    lock = threading.Lock()
    timers = {}

    def process(fp):
        with lock:
            timers.pop(fp, None)
        p = Path(fp)
        try:
            if not p.is_file() or _in_quarantine(p):
                return
        except OSError:
            return
        fds = scan_file(p, db, ctx)
        real = [fd for fd in fds if fd.get("level") != "error"]
        stats["scanned"] += 1
        stats["findings"] += len(real)
        if real and not quiet:
            for fd in real:
                print(f"[x] {p}: [{fd['level'].upper()}] {fd['name']} — "
                      f"{fd.get('detail', '')}")
        if quarantine and real:
            high = next((fd for fd in real if fd["level"] == "high"), None)
            if high:
                try:
                    qn = quarantine_file(p, high)
                    stats["quarantined"] += 1
                    print(f"    -> 已隔离: {qn}")
                except OSError as exc:
                    print(f"[!] 隔离失败 {p}: {exc}")
        if on_result:
            try:
                on_result(p, real)
            except Exception:
                pass

    def schedule(fp):
        with lock:
            old = timers.pop(fp, None)
            if old:
                old.cancel()
            t = threading.Timer(DEBOUNCE, process, args=(fp,))
            timers[fp] = t
        t.start()

    observer = Observer()
    observer.schedule(_Handler(schedule), str(root), recursive=True)
    observer.start()
    if not quiet:
        print(f"[i] 正在监视 {root} （Ctrl+C 停止）")
    try:
        while not stop.is_set():
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join(timeout=2)
        with lock:
            for t in timers.values():
                t.cancel()
    return stats
