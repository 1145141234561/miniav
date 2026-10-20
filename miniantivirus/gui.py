"""tkinter 图形界面：扫描 / 行为分析 / 实时监视 / 隔离区管理 / 自检。

所有耗时操作放后台线程；print 重定向到队列，由 UI 线程 after() 轮询刷新，
兼容 PyInstaller --windowed 打包（stdout 为 None）。
"""

import argparse
import io
import queue
import sys
import threading
import time
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from . import analyzer, report, scanner, selftest
from .scanner import (_in_quarantine, quarantine_file, quarantine_restore,
                      scan_file)
from .signatures import (QUAR_DIR, SIG_DB, default_db, ensure_data_files,
                         load_db, save_db)

LEVEL_TAGS = {
    "high": ("#C0392B", "#F1948A"),
    "medium": ("#B9770E", "#F5B041"),
    "low": ("#5D6D7E", "#85929E"),
}


class _LogRedirect(io.TextIOBase):
    """把 print 输出转入队列（windowed exe 下 stdout 为 None，必须重定向）。"""

    def __init__(self, q):
        self._q = q

    def write(self, s):
        if s:
            self._q.put(("log", s))
        return len(s)

    def flush(self):
        pass

    def isatty(self):
        return False


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MiniAV 防御工具 v2.0")
        self.minsize(860, 560)
        self._q = queue.Queue()
        self._stop = threading.Event()
        self._watch_stop = threading.Event()
        self._busy = False
        self._last_rows = []
        sys.stdout = sys.stderr = _LogRedirect(self._q)

        self._build_ui()
        self.after(80, self._poll)
        self.after(600, self._autoload)   # 启动即自动加载进程保护驱动
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        from .vt import VTClient
        if not VTClient.has_key():
            self.var_vt.set(False)
            self.chk_vt.state(["disabled"])
            self._log("[i] 未检测到 VT_API_KEY 环境变量，VT 信誉查询不可用\n")
        if not scanner.HAS_YARA:
            self._log("[i] 未安装 yara-python，YARA 规则引擎不可用\n")

    # ---------- UI ----------

    def _build_ui(self):
        f = ttk.Frame(self, padding=8)
        f.pack(fill="both", expand=True)

        row1 = ttk.Frame(f)
        row1.pack(fill="x", pady=(0, 6))
        ttk.Label(row1, text="目标:").pack(side="left")
        self.var_target = tk.StringVar()
        ttk.Entry(row1, textvariable=self.var_target).pack(
            side="left", fill="x", expand=True, padx=4)
        ttk.Button(row1, text="选文件", width=8,
                   command=lambda: self._pick(file=False)).pack(side="left", padx=2)
        ttk.Button(row1, text="选目录", width=8,
                   command=lambda: self._pick(file=True)).pack(side="left", padx=2)

        row2 = ttk.Frame(f)
        row2.pack(fill="x", pady=(0, 6))
        self.var_yara = tk.BooleanVar(value=True)
        self.var_vt = tk.BooleanVar(value=True)
        self.var_sigcheck = tk.BooleanVar(value=False)
        self.var_fast = tk.BooleanVar(value=False)
        self.var_quar = tk.BooleanVar(value=False)
        self.chk_vt = ttk.Checkbutton(row2, text="VT 哈希信誉", variable=self.var_vt)
        ttk.Checkbutton(row2, text="YARA 规则 (rules/)", variable=self.var_yara).pack(side="left")
        self.chk_vt.pack(side="left", padx=(10, 0))
        ttk.Checkbutton(row2, text="PE 签名校验", variable=self.var_sigcheck).pack(
            side="left", padx=(10, 0))
        ttk.Checkbutton(row2, text="增量加速", variable=self.var_fast).pack(
            side="left", padx=(10, 0))
        ttk.Checkbutton(row2, text="自动隔离 high", variable=self.var_quar).pack(
            side="left", padx=(10, 0))

        row3 = ttk.Frame(f)
        row3.pack(fill="x", pady=(0, 6))
        self.btn_scan = ttk.Button(row3, text="开始扫描", command=self._start_scan)
        self.btn_scan.pack(side="left")
        self.btn_stop = ttk.Button(row3, text="停止", command=self._stop_scan,
                                   state="disabled")
        self.btn_stop.pack(side="left", padx=4)
        self.btn_watch = ttk.Button(row3, text="开始监视", command=self._toggle_watch)
        self.btn_watch.pack(side="left", padx=(12, 0))
        ttk.Button(row3, text="样本分析", command=self._analyze).pack(side="left", padx=4)
        ttk.Button(row3, text="离线扫描", command=self._offline).pack(side="left", padx=4)
        ttk.Button(row3, text="启动项检查", command=self._autoruns).pack(side="left", padx=4)
        ttk.Button(row3, text="进程检查", command=self._procs).pack(side="left", padx=4)
        ttk.Button(row3, text="自保护", command=self._guard).pack(side="left", padx=4)
        ttk.Button(row3, text="进程保护", command=self._protect).pack(side="left", padx=4)
        ttk.Button(row3, text="隔离区…", command=self._quar_dialog).pack(side="left", padx=4)
        ttk.Button(row3, text="驱动体检", command=self._drivers).pack(side="left", padx=4)
        ttk.Button(row3, text="签名库…", command=self._sigdb_dialog).pack(side="left", padx=4)
        ttk.Button(row3, text="自检", command=self._selftest).pack(side="left", padx=4)
        ttk.Button(row3, text="生成报告", command=self._report).pack(side="left", padx=4)

        pan = ttk.Panedwindow(f, orient="vertical")
        pan.pack(fill="both", expand=True)

        cols = ("path", "level", "name", "detail")
        wrap = ttk.Frame(pan)
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", height=9)
        for cid, text, w in (("path", "文件", 300), ("level", "级别", 60),
                             ("name", "检出项", 180), ("detail", "详情", 260)):
            self.tree.heading(cid, text=text)
            self.tree.column(cid, width=w, anchor="w")
        ysb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="left", fill="y")
        for lv, (dark, light) in LEVEL_TAGS.items():
            self.tree.tag_configure(lv, foreground=dark)
        pan.add(wrap, weight=3)

        logw = ttk.Frame(pan)
        self.txt = tk.Text(logw, height=8, wrap="word", state="disabled",
                           font=("Consolas", 9), background="#111418",
                           foreground="#D5D8DC")
        lsb = ttk.Scrollbar(logw, orient="vertical", command=self.txt.yview)
        self.txt.configure(yscrollcommand=lsb.set)
        self.txt.pack(side="left", fill="both", expand=True)
        lsb.pack(side="left", fill="y")
        pan.add(logw, weight=2)

        self.var_status = tk.StringVar(value="就绪")
        ttk.Label(f, textvariable=self.var_status, anchor="w").pack(
            fill="x", pady=(6, 0))

    def _pick(self, file):
        if file:
            p = filedialog.askdirectory(title="选择扫描目录")
        else:
            p = filedialog.askopenfilename(title="选择文件")
        if p:
            self.var_target.set(p)

    # ---------- 队列消费 ----------

    def _poll(self):
        try:
            while True:
                msg = self._q.get_nowait()
                kind = msg[0]
                if kind == "log":
                    self._log(msg[1])
                elif kind == "finding":
                    self._add_finding(msg[1])
                elif kind == "progress":
                    self.var_status.set(f"已扫 {msg[1]} 文件 · 检出 {msg[2]} 条")
                elif kind == "done":
                    _, rows, s, d, target = msg
                    self._busy = False
                    self._last_rows = rows
                    self.btn_scan.state(["!disabled"])
                    self.btn_stop.state(["disabled"])
                    try:
                        scanner.flush_cache()
                    except Exception:
                        pass
                    self.var_status.set(
                        f"扫描完成: {s} 文件 · 检出 {d} 条  ({target})")
                elif kind == "selftest":
                    _, code = msg
                    self._busy = False
                    self.btn_scan.state(["!disabled"])
                    self.btn_stop.state(["disabled"])
                    if code == 0:
                        messagebox.showinfo("自检", "全部自检项通过（详情见日志）。")
                    else:
                        messagebox.showwarning("自检", "存在失败项，请查看日志。")
                elif kind == "guard_done":
                    _, code = msg
                    if code == 1:
                        messagebox.showwarning("自保护", "检测到完整性异常，请查看日志。")
                    else:
                        messagebox.showinfo("自保护", "完整性校验正常（详情见日志）。")
                elif kind == "procs_done":
                    _, code = msg
                    if code == 1:
                        messagebox.showwarning("进程检查", "发现可疑进程，请查看日志。")
                    else:
                        messagebox.showinfo("进程检查", "检查完成，未发现可疑进程（详情见日志）。")
                elif kind == "protect_done":
                    _, code = msg
                    if code == 1:
                        messagebox.showwarning(
                            "进程保护",
                            "自保护驱动未加载，保护未生效。\n安装与启动步骤见日志。")
                    elif code == 0:
                        ans = messagebox.askyesnocancel(
                            "进程保护",
                            "驱动已加载。\n\n是：启用进程保护\n否：停用进程保护\n"
                            "取消：仅查看状态")
                        if ans is not None:
                            threading.Thread(
                                target=self._protect_enable_worker,
                                args=(ans,), daemon=True).start()
                elif kind == "protect_final":
                    _, ok = msg
                    if ok:
                        messagebox.showinfo("进程保护", "操作完成（详情见日志）。")
                    else:
                        messagebox.showwarning("进程保护", "操作失败，请查看日志。")
                elif kind == "autoruns_done":
                    _, code = msg
                    if code == 1:
                        messagebox.showwarning("启动项检查", "发现可疑持久化项，请查看日志。")
                    else:
                        messagebox.showinfo("启动项检查", "检查完成，未发现可疑项（详情见日志）。")
                elif kind == "offline_done":
                    _, code = msg
                    if code == 1:
                        messagebox.showwarning("离线扫描", "发现检出项，请查看日志。")
                    else:
                        messagebox.showinfo("离线扫描", "离线扫描完成，未发现检出（详情见日志）。")
                elif kind == "learn_ask":
                    _, cands = msg
                    if messagebox.askyesno(
                            "自动学习",
                            f"分析发现 {len(cands)} 个恶意样本。\n\n"
                            "是否自动提取特征入库？\n"
                            "（哈希签名 + 自动 YARA 规则，可随时在签名库中移除）"):
                        threading.Thread(target=self._learn_worker,
                                         args=(cands,), daemon=True).start()
                elif kind == "learn_done":
                    _, code = msg
                    if code == 0:
                        messagebox.showinfo("自动学习", "特征已入库并保存（详情见日志）。")
                    else:
                        messagebox.showwarning("自动学习", "没有新特征入库（详情见日志）。")
                elif kind == "drivers":
                    _, code = msg
                    self._busy = False
                    self.btn_scan.state(["!disabled"])
                    self.btn_stop.state(["disabled"])
                    if code == 1:
                        messagebox.showwarning(
                            "驱动体检", "发现可疑/异常驱动，请查看日志。")
                    elif code == 0:
                        messagebox.showinfo(
                            "驱动体检", "体检完成，未发现异常（详情见日志）。")
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _log(self, text):
        self.txt.configure(state="normal")
        self.txt.insert("end", text)
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def _add_finding(self, row):
        tag = row.get("level", "low")
        self.tree.insert("", "end", values=(
            row.get("path", ""), tag.upper(), row.get("name", ""),
            row.get("detail", "")), tags=(tag,))

    # ---------- 扫描 ----------

    def _make_ctx(self, db):
        from .cli import build_ctx
        args = argparse.Namespace(
            rules=None, exclude=[], vt=self.var_vt.get(),
            sigcheck=self.var_sigcheck.get(), quarantine=self.var_quar.get(),
            report=None, jobs=1, fast=self.var_fast.get())
        return build_ctx(args, db)

    def _start_scan(self):
        target = Path(self.var_target.get().strip('" '))
        if not target.exists():
            messagebox.showerror("错误", f"路径不存在:\n{target}")
            return
        db = self._load_db_safe()
        if db is None:
            return
        self.tree.delete(*self.tree.get_children())
        self._last_rows = []
        self._stop.clear()
        self._busy = True
        self.btn_scan.state(["disabled"])
        self.btn_stop.state(["!disabled"])
        self.var_status.set("扫描中…")
        self._log(f"\n[i] 开始扫描: {target}\n")
        threading.Thread(target=self._scan_worker,
                         args=(target, db), daemon=True).start()

    def _scan_worker(self, target, db):
        try:
            ctx = self._make_ctx(db)
            files = ([target] if target.is_file() else
                     sorted(p for p in target.rglob("*")
                            if p.is_file() and not _in_quarantine(p)))
            rows, scanned, detected = [], 0, 0
            for f in files:
                if self._stop.is_set():
                    self._q.put(("log", "[i] 已按用户要求中止扫描\n"))
                    break
                fds = scan_file(f, db, ctx)
                for fd in fds:
                    if fd.get("level") == "error":
                        self._q.put(("log", f"[!] {f}: {fd['name']}\n"))
                        continue
                    detected += 1
                    row = {"path": str(f), **fd}
                    rows.append(row)
                    self._q.put(("finding", row))
                if self.var_quar.get():
                    high = next((fd for fd in fds if fd.get("level") == "high"), None)
                    if high:
                        try:
                            qname = quarantine_file(f, high)
                            self._q.put(("log", f"    -> 已隔离: {qname}\n"))
                        except OSError as exc:
                            self._q.put(("log", f"[!] 隔离失败 {f}: {exc}\n"))
                scanned += 1
                self._q.put(("progress", scanned, detected))
            self._q.put(("done", rows, scanned, detected, str(target)))
        except Exception:
            self._q.put(("log", "[!] 扫描线程异常:\n" + traceback.format_exc()))
            self._q.put(("done", [], 0, 0, str(target)))

    def _stop_scan(self):
        self._stop.set()
        self.var_status.set("正在停止…")

    # ---------- 监视 ----------

    def _toggle_watch(self):
        if self.btn_watch.cget("text") == "开始监视":
            target = Path(self.var_target.get().strip('" '))
            if not target.is_dir():
                messagebox.showerror("错误", "监视需要选择一个目录")
                return
            db = self._load_db_safe()
            if db is None:
                return
            self._watch_stop.clear()
            self.btn_watch.configure(text="停止监视")
            self._log(f"\n[i] 开始实时监视: {target}\n")
            threading.Thread(
                target=self._watch_worker, args=(target, db), daemon=True).start()
        else:
            self._watch_stop.set()
            self.btn_watch.configure(text="开始监视")
            self._log("[i] 正在停止监视…\n")

    def _watch_worker(self, target, db):
        from . import watcher
        try:
            ctx = self._make_ctx(db)
            stats = watcher.watch(
                str(target), db, ctx, quarantine=self.var_quar.get(),
                stop_event=self._watch_stop,
                on_result=lambda p, fds: [self._q.put(("finding", {"path": str(p), **fd}))
                                          for fd in fds if fd.get("level") != "error"])
            self._q.put(("log", f"\n[i] 监视结束: 扫描 {stats['scanned']} 次, "
                                f"检出 {stats['findings']} 条\n"))
        except RuntimeError as exc:
            self._q.put(("log", f"[!] {exc}\n"))
        except Exception:
            self._q.put(("log", "[!] 监视线程异常:\n" + traceback.format_exc()))
        self.btn_watch.configure(text="开始监视")

    # ---------- 样本分析 ----------

    def _analyze(self):
        target = Path(self.var_target.get().strip('" '))
        if not target.exists():
            messagebox.showerror("错误", f"路径不存在:\n{target}")
            return
        self._log(f"\n[i] 样本深度分析: {target}（绝不执行样本）\n")
        threading.Thread(target=self._analyze_worker, args=(target,),
                         daemon=True).start()

    def _analyze_worker(self, target):
        try:
            db = self._load_db_safe()
            if db is None:
                return
            ctx = self._make_ctx(db)
            files = ([target] if target.is_file() else
                     sorted(p for p in target.rglob("*") if p.is_file()))
            bad = 0
            learn_cands = []
            for f in files:
                try:
                    result = analyzer.analyze_sample(f, db, ctx=ctx)
                    if result["verdict"] != "清洁":
                        bad += 1
                        self._q.put(("log", analyzer.format_report(result) + "\n\n"))
                    if result["verdict"] == "恶意":
                        learn_cands.append(result)
                except Exception as exc:
                    self._q.put(("log", f"[!] {f}: {exc}\n"))
            self._q.put(("log", f"[i] 样本分析完成: {len(files)} 个文件, "
                                f"非清洁 {bad} 个（仅列出非清洁结果）\n"))
            if learn_cands:
                self._q.put(("learn_ask", learn_cands))
        except Exception:
            self._q.put(("log", traceback.format_exc()))

    # ---------- 自动学习特征 ----------

    def _learn_worker(self, results):
        try:
            db = self._load_db_safe()
            if db is None:
                return
            from . import autolearn
            ok = 0
            for result in results:
                ls = autolearn.learn_from_result(result, db)
                if ls["learned"]:
                    ok += 1
                self._q.put(("log", autolearn.format_summary(ls) + "\n"))
            if ok:
                save_db(db)
                self._q.put(("learn_done", 0))
            else:
                self._q.put(("learn_done", 1))
        except Exception:
            self._q.put(("log", traceback.format_exc()))
            self._q.put(("learn_done", 1))

    # ---------- 离线扫描 ----------

    def _offline(self):
        target = Path(self.var_target.get().strip('" '))
        if not target.exists():
            messagebox.showerror("错误", f"路径不存在:\n{target}")
            return
        pack_file = filedialog.askopenfilename(
            title="选择离线特征包（取消则使用本地签名库）",
            filetypes=[("特征包", "*.zip"), ("所有文件", "*.*")])
        self._log(f"\n[i] 离线扫描（不访问网络）: {target}"
                  f" · 特征: {pack_file or '本地签名库'}\n")
        threading.Thread(target=self._offline_worker,
                         args=(target, pack_file or None),
                         daemon=True).start()

    def _offline_worker(self, target, pack_file):
        try:
            from .cli import cmd_offline
            args = argparse.Namespace(
                path=str(target), pack=pack_file, exclude=[],
                report=None, sigcheck=False,
                quarantine=self.var_quar.get())
            code = cmd_offline(args)
            self._q.put(("offline_done", code))
        except SystemExit as exc:
            self._q.put(("log", f"[!] {exc}\n"))
        except Exception:
            self._q.put(("log", "[!] 离线扫描异常:\n" + traceback.format_exc()))

    # ---------- 启动项检查 ----------

    def _autoruns(self):
        self._log("\n[i] 启动项安全检查（只读，不执行任何启动项）\n")
        threading.Thread(target=self._autoruns_worker, daemon=True).start()

    def _autoruns_worker(self):
        try:
            from .cli import cmd_autoruns
            code = cmd_autoruns(argparse.Namespace())
            self._q.put(("autoruns_done", code))
        except Exception:
            self._q.put(("log", "[!] 启动项检查异常:\n" + traceback.format_exc()))

    # ---------- 进程检查 ----------

    def _procs(self):
        self._log("\n[i] 进程安全检查（只读快照，不注入不终止）\n")
        threading.Thread(target=self._procs_worker, daemon=True).start()

    def _procs_worker(self):
        try:
            from .cli import cmd_procs
            code = cmd_procs(argparse.Namespace())
            self._q.put(("procs_done", code))
        except Exception:
            self._q.put(("log", "[!] 进程检查异常:\n" + traceback.format_exc()))

    # ---------- 自保护 ----------

    def _guard(self):
        self._log("\n[i] 自保护校验（完整性基线对比）\n")
        threading.Thread(target=self._guard_worker, daemon=True).start()

    def _guard_worker(self):
        try:
            from . import selfguard
            from .wintrust import HAS_WINTRUST, verify_embedded
            if not selfguard.MANIFEST().is_file():
                self._q.put(("log", "[i] 首次运行：自动建立完整性基线\n"))
                exe = (Path(sys.executable)
                       if getattr(sys, "frozen", False) else None)
                selfguard.baseline(
                    extra=[exe] if exe and exe.is_file() else None)
            res = selfguard.check()
            exe_signed = None
            if getattr(sys, "frozen", False) and HAS_WINTRUST:
                exe_signed = verify_embedded(sys.executable)[0]
            self._q.put(("log", selfguard.format_report(res, exe_signed) + "\n"))
            self._q.put(("guard_done",
                         1 if (res["modified"] or res["missing"]) else 0))
        except Exception:
            self._q.put(("log", "[!] 自保护校验异常:\n" + traceback.format_exc()))

    # ---------- 进程保护（内核驱动） ----------

    def _autoload(self):
        """程序启动即自动安装/启动进程保护驱动（失败仅记日志不打扰）。"""
        threading.Thread(target=self._autoload_worker, daemon=True).start()

    def _autoload_worker(self):
        try:
            from . import driverprotect
            d, err = driverprotect.ensure_loaded()
            if d is None:
                self._q.put(("log", "[i] 进程保护未自动加载: " + str(err) +
                             "\n    提示: 以管理员身份运行可自动安装驱动\n"))
                return
            self._q.put(("log", "[i] 进程保护自动加载: " +
                         ("已启用" if d["enabled"] else "已停用") +
                         f" · 保护对象 {d['name']}\n"))
        except Exception:
            self._q.put(("log", "[!] 进程保护自动加载异常:\n" +
                         traceback.format_exc()))

    def _protect(self):
        self._log("\n[i] 进程保护（MiniAVProt 内核驱动）\n")
        threading.Thread(target=self._protect_worker, daemon=True).start()

    def _protect_worker(self):
        try:
            from . import driverprotect
            d, err = driverprotect.safe_status()
            if d is None:
                self._q.put(("log", "[!] 自保护驱动未加载或无法访问: " +
                             str(err) + "\n" + driverprotect.LOAD_HINT + "\n"))
                self._q.put(("protect_done", 1))
                return
            self._q.put(("log", driverprotect.format_report(d) + "\n"))
            self._q.put(("protect_done", 0))
        except Exception:
            self._q.put(("log", "[!] 进程保护异常:\n" + traceback.format_exc()))
            self._q.put(("protect_done", 2))

    def _protect_enable_worker(self, on):
        try:
            from . import driverprotect
            driverprotect.enable(on)
            d, err = driverprotect.safe_status()
            if d is None:
                self._q.put(("log", f"[!] 查询状态失败: {err}\n"))
                self._q.put(("protect_final", False))
                return
            state = "已启用" if d["enabled"] else "已停用"
            self._q.put(("log", f"[+] 进程保护当前状态: {state}\n"))
            self._q.put(("protect_final", True))
        except PermissionError:
            self._q.put(("log", "[!] 修改保护状态需要管理员权限"
                                "（请以管理员身份运行 MiniAV）\n"))
            self._q.put(("protect_final", False))
        except Exception as exc:
            self._q.put(("log", f"[!] 进程保护异常: {exc}\n"))
            self._q.put(("protect_final", False))

    # ---------- 签名库管理 ----------

    def _sigdb_dialog(self):
        from . import sigdb
        win = tk.Toplevel(self)
        win.title("签名库管理")
        win.geometry("880x480")

        db = self._load_db_safe() or default_db()
        cols = ("kind", "algo", "value", "name", "level")
        wrap = ttk.Frame(win)
        wrap.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        tree = ttk.Treeview(wrap, columns=cols, show="headings", height=12)
        for cid, text, w in (("kind", "类型", 60), ("algo", "算法/类型", 80),
                             ("value", "摘要/模式", 380), ("name", "名称", 180),
                             ("level", "级别", 70)):
            tree.heading(cid, text=text)
            tree.column(cid, width=w, anchor="w")
        ysb = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=ysb.set)
        tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="left", fill="y")

        var_stats = tk.StringVar()
        ttk.Label(win, textvariable=var_stats, anchor="w").pack(
            fill="x", padx=8)

        def reload():
            tree.delete(*tree.get_children())
            for algo, digest, name, level in sigdb.iter_hashes(db):
                tree.insert("", "end", iid=f"h:{digest}",
                            values=("哈希", algo, digest, name, level),
                            tags=(level,))
            for i, sig in enumerate(db.get("patterns", [])):
                lv = sig.get("level", "medium")
                tree.insert("", "end", iid=f"p:{i}",
                            values=("模式", sig.get("type"),
                                    str(sig.get("data", ""))[:72],
                                    sig.get("name", "Unknown"), lv), tags=(lv,))
            tree.tag_configure("high", foreground="#C0392B")
            tree.tag_configure("medium", foreground="#B9770E")
            tree.tag_configure("low", foreground="#5D6D7E")
            s = sigdb.stats(db)
            var_stats.set(
                f"哈希签名: md5={s['md5']}  sha1={s['sha1']}  sha256={s['sha256']}"
                f"   模式签名: {s['patterns']}   白名单: {s['whitelist']}"
                f"   漏洞驱动: {s['vulnerable_drivers']}")

        def _ask_level(default="high"):
            lv = simpledialog.askstring(
                "级别", "威胁级别 high/medium/low:", initialvalue=default,
                parent=win)
            return lv or default

        def do_add_sample():
            p = filedialog.askopenfilename(title="选择样本文件", parent=win)
            if not p:
                return
            name = simpledialog.askstring("签名名称", "输入签名名称:",
                                          initialvalue=Path(p).stem, parent=win)
            if not name:
                return
            try:
                hashes, is_new = sigdb.add_sample(
                    db, Path(p), name, _ask_level())
                save_db(db)
                reload()
                self._log(f"[i] 签名库{'新增' if is_new else '更新'}样本 {name}: "
                          f"sha256={hashes['sha256']}\n")
            except sigdb.SigdbError as exc:
                messagebox.showerror("错误", str(exc), parent=win)

        def do_add_hash():
            algo = simpledialog.askstring("添加哈希", "算法 md5/sha1/sha256:",
                                          initialvalue="sha256", parent=win)
            if not algo:
                return
            digest = simpledialog.askstring("添加哈希", "输入摘要:", parent=win)
            if not digest:
                return
            name = simpledialog.askstring("签名名称", "输入签名名称:", parent=win)
            if not name:
                return
            try:
                a, d, is_new = sigdb.add_hash(db, digest, name,
                                              level=_ask_level(), algo=algo)
                save_db(db)
                reload()
                self._log(f"[i] 签名库{'新增' if is_new else '更新'} {a} {d} {name}\n")
            except sigdb.SigdbError as exc:
                messagebox.showerror("错误", str(exc), parent=win)

        def do_add_pattern():
            ptype = simpledialog.askstring("添加模式", "类型 regex/hex:",
                                           initialvalue="regex", parent=win)
            if not ptype:
                return
            data = simpledialog.askstring("添加模式", "模式内容:", parent=win)
            if not data:
                return
            name = simpledialog.askstring("签名名称", "输入签名名称:", parent=win)
            if not name:
                return
            try:
                is_new = sigdb.add_pattern(db, ptype, data, name,
                                           level=_ask_level("medium"))
                save_db(db)
                reload()
                self._log(f"[i] 签名库{'新增' if is_new else '已有'}模式 {name}\n")
            except sigdb.SigdbError as exc:
                messagebox.showerror("错误", str(exc), parent=win)

        def do_delete():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("提示", "先在列表中选择要删除的签名", parent=win)
                return
            try:
                for iid in sel:
                    if iid.startswith("h:"):
                        sigdb.remove_hash(db, iid[2:])
                    elif iid.startswith("p:"):
                        sigdb.remove_pattern(db, int(iid[2:]))
                save_db(db)
                reload()
                self._log(f"[i] 已删除 {len(sel)} 条签名\n")
            except sigdb.SigdbError as exc:
                messagebox.showerror("错误", str(exc), parent=win)

        def do_import():
            p = filedialog.askopenfilename(
                title="导入签名（JSON/CSV）", parent=win,
                filetypes=[("签名文件", "*.json *.csv"), ("全部文件", "*.*")])
            if not p:
                return
            try:
                added = sigdb.import_file(db, p)
                save_db(db)
                reload()
                messagebox.showinfo(
                    "导入完成",
                    f"新增哈希 {added['hashes']} 条\n新增模式 {added['patterns']} 条"
                    f"\n跳过 {added['skipped']} 条", parent=win)
                self._log(f"[i] 签名库导入: {p} -> 哈希 {added['hashes']} 条\n")
            except (sigdb.SigdbError, OSError) as exc:
                messagebox.showerror("导入失败", str(exc), parent=win)

        def do_export():
            p = filedialog.asksaveasfilename(
                title="导出签名库", parent=win, defaultextension=".json",
                initialfile="signatures_export.json",
                filetypes=[("JSON 完整库", "*.json"), ("CSV 平面表", "*.csv")])
            if not p:
                return
            fmt = "csv" if p.lower().endswith(".csv") else "json"
            try:
                n = sigdb.export_file(db, p, fmt)
                messagebox.showinfo("导出完成", f"已导出 {n} 条签名", parent=win)
                self._log(f"[i] 签名库导出: {p} ({fmt}, {n} 条)\n")
            except (sigdb.SigdbError, OSError) as exc:
                messagebox.showerror("导出失败", str(exc), parent=win)

        btns = ttk.Frame(win)
        btns.pack(fill="x", padx=8, pady=(4, 8))
        for text, cmd in (("添加样本…", do_add_sample), ("添加哈希…", do_add_hash),
                          ("添加模式…", do_add_pattern), ("删除所选", do_delete),
                          ("导入…", do_import), ("导出…", do_export)):
            ttk.Button(btns, text=text, command=cmd).pack(side="left", padx=3)

        reload()

    # ---------- 驱动体检 / 自检 / 报告 / 隔离区 ----------

    def _drivers(self):
        if self._busy:
            messagebox.showinfo("提示", "有任务正在进行中")
            return
        self._busy = True
        self.btn_scan.state(["disabled"])
        self.btn_stop.state(["!disabled"])
        self._log("\n[i] 系统内核驱动体检（签名 + BYOVD 黑名单）…\n")
        threading.Thread(target=self._drivers_worker, daemon=True).start()

    def _drivers_worker(self):
        code = 0
        try:
            from .cli import cmd_drivers
            code = cmd_drivers(None) or 0
        except SystemExit as exc:
            self._q.put(("log", f"[!] {exc}\n"))
            code = 2
        except Exception:
            self._q.put(("log", "[!] 驱动体检线程异常:\n" + traceback.format_exc()))
            code = 2
        self._q.put(("drivers", code))

    def _selftest(self):
        if self._busy:
            messagebox.showinfo("提示", "有任务正在进行中")
            return
        self._busy = True
        self.btn_scan.state(["disabled"])
        self.btn_stop.state(["!disabled"])
        self._log("\n[i] 开始端到端自检…\n")
        db = self._load_db_safe() or default_db()
        threading.Thread(
            target=lambda: self._q.put(("selftest", _run_selftest(db))),
            daemon=True).start()

    def _report(self):
        if not self._last_rows:
            messagebox.showinfo("提示", "当前没有扫描结果，请先扫描")
            return
        dest = filedialog.asksaveasfilename(
            defaultextension=".html", initialfile="scan_report.html",
            filetypes=[("HTML 报告", "*.html")])
        if not dest:
            return
        meta = {"target": self.var_target.get(),
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "files": len(self._last_rows),
                "findings": len(self._last_rows)}
        try:
            out = report.write_html(dest, meta, self._last_rows)
        except OSError as exc:
            messagebox.showerror("错误", f"报告生成失败:\n{exc}")
            return
        self._log(f"[i] HTML 报告已生成: {out}\n")
        messagebox.showinfo("报告", f"已生成:\n{out}")

    def _quar_dialog(self):
        win = tk.Toplevel(self)
        win.title("隔离区管理")
        win.geometry("720x320")
        win.transient(self)
        cols = ("qname", "original", "finding", "time")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for cid, text, w in (("qname", "隔离名", 190), ("original", "原路径", 240),
                             ("finding", "检出项", 140), ("time", "时间", 110)):
            tree.heading(cid, text=text)
            tree.column(cid, width=w, anchor="w")
        tree.pack(fill="both", expand=True, padx=8, pady=8)

        metas = []
        if QUAR_DIR.exists():
            import json
            for m in sorted(QUAR_DIR.glob("*.meta.json")):
                try:
                    d = json.loads(m.read_text(encoding="utf-8"))
                    metas.append(d)
                    tree.insert("", "end", iid=d["name"], values=(
                        d["name"], d["original"], d["finding"], d["time"]))
                except (OSError, ValueError, KeyError):
                    continue

        btns = ttk.Frame(win)
        btns.pack(fill="x", padx=8, pady=(0, 8))

        def _restore():
            sel = tree.selection()
            if not sel:
                return
            if not messagebox.askyesno("恢复", f"把 {sel[0]} 恢复到原位置？"):
                return
            try:
                dst = quarantine_restore(sel[0])
            except SystemExit as exc:
                messagebox.showerror("错误", str(exc))
                return
            self._log(f"[+] 已恢复隔离文件到: {dst}\n")
            tree.delete(sel[0])

        def _delete():
            sel = tree.selection()
            if not sel:
                return
            qname = sel[0]
            if not messagebox.askyesno("彻底删除",
                                       f"从隔离区彻底删除 {qname}？不可恢复"):
                return
            for suffix in ("", ".meta.json"):
                p = QUAR_DIR / (qname + suffix)
                try:
                    p.unlink()
                except OSError as exc:
                    messagebox.showerror("错误", f"删除失败: {exc}")
                    return
            self._log(f"[+] 已彻底删除隔离文件: {qname}\n")
            tree.delete(qname)

        ttk.Button(btns, text="恢复到原位置", command=_restore).pack(side="left")
        ttk.Button(btns, text="彻底删除", command=_delete).pack(side="left", padx=6)
        if not metas:
            ttk.Label(win, text="隔离区为空").pack()

    # ---------- 杂项 ----------

    def _load_db_safe(self):
        try:
            return load_db()
        except SystemExit as exc:
            # 签名库缺失/损坏：提供重建
            if messagebox.askyesno("签名库缺失",
                                   f"{exc}\n\n用默认空签名库重建吗？"):
                db = default_db()
                save_db(db)
                return db
            return None

    def _on_close(self):
        self._stop.set()
        self._watch_stop.set()
        self.destroy()


def _run_selftest(db):
    """独立函数方便线程调用；print 已被重定向到日志队列。"""
    try:
        return selftest.run(db)
    except Exception:
        traceback.print_exc()
        return 1


def _smoke():
    """打包验证模式：MiniAV.exe --smoke 跑自检并写结果文件后退出。

    每个阶段即时落盘，若进程被外部终止（如杀软行为拦截）也能定位死因。
    """
    result = io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout = sys.stderr = result
    base = Path(sys.executable).parent if getattr(sys, "frozen", False) \
        else Path.cwd()
    marker = base / "smoke_result.txt"

    def flush():
        try:
            marker.write_text(result.getvalue(), encoding="utf-8")
        except OSError:
            pass

    code = 1
    try:
        import tkinter as _tk
        r = _tk.Tk()
        r.withdraw()
        r.destroy()
        result.write("tkinter OK\n")
        from .vt import VTClient
        result.write(f"yara={scanner.HAS_YARA} "
                     f"vt_key={VTClient.has_key()}\n")
        flush()
        ensure_data_files()
        db = default_db() if not SIG_DB.exists() else load_db()
        result.write("selftest 开始\n")
        flush()
        code = selftest.run(db)
        result.write(f"selftest 结束 exit={code}\n")
        flush()
    except BaseException:
        result.write(traceback.format_exc())
        code = 1
        flush()
    finally:
        sys.stdout, sys.stderr = old_out, old_err
        flush()
    return code


def main(argv=None):
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--smoke" in argv:
        raise SystemExit(_smoke())
    ensure_data_files()
    App().mainloop()
