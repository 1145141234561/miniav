"""静态行为分析器：从脚本/宏文本提取行为特征并评分。

设计原则：绝不执行样本，只做文本级行为链分析，因此对分析者零风险。
评分模型：单条特征按危害加权，特定组合（下载+动态执行）追加组合分。
判定：score >= 4 恶意，>= 2 可疑，否则清洁。
"""

import re
from pathlib import Path

try:
    from oletools.olevba import VBA_Parser
    HAS_OLETOOLS = True
except ImportError:
    HAS_OLETOOLS = False

# (规则名, 正则, 权重, 描述)
RULES = [
    ("SBX-AntiDefense",
     re.compile(r"(?i)(set-mppreference|add-mppreference|"
                r"vssadmin\s+delete\s+shadows|wmic\s+\S*shadowcopy\s+delete|"
                r"bcdedit\s+/set\s+\S*safeboot)"), 3,
     "试图关闭/规避安全防护或删除卷影副本"),
    ("SBX-CredAccess",
     re.compile(r"(?i)(mimikatz|sekurlsa|lsadump|"
                r"netsh\s+wlan\s+show\s+profile|getnetworkcredential)"), 2,
     "凭据窃取相关操作"),
    ("SBX-Persistence",
     re.compile(r"(?i)(currentversion.{0,4}run\b|schtasks\s+/create|"
                r"sc\s+create\s|new-service\b)"), 2,
     "注册表 Run 键 / 计划任务 / 服务等持久化手法"),
    ("SBX-Macro-AutoExec",
     re.compile(r"(?i)\b(auto_?open|auto_?exec|document_?open|workbook_?open)\b"), 2,
     "宏自动启动入口（打开文档即触发）"),
    ("SBX-Remote-Download",
     re.compile(r"(?i)(downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|"
                r"certutil\s+-{1,2}urlcache|bitsadmin\s+/transfer|"
                r"wget\s+https?://|curl\s+-{1,2}[a-z]+\s+https?://)"), 2,
     "从远程服务器下载内容"),
    ("SBX-Dynamic-Exec",
     re.compile(r"(?i)(invoke-expression|\biex\b|\beval\s*\(|os\.system\s*\(|"
                r"subprocess\.(call|run|popen)\b|"
                r"createobject\s*\(\s*[\"']wscript\.shell)"), 1,
     "动态执行代码（把字符串当代码运行）"),
    ("SBX-Encoded-Payload",
     re.compile(r"(?i)(frombase64string|-(enc|encodedcommand)\s|base64\s+(-d|-decode))"), 1,
     "使用编码载荷隐藏真实意图"),
    ("SBX-Recon",
     re.compile(r"(?i)\b(whoami|ipconfig|systeminfo|tasklist|net\s+user|"
                r"query\s+user|get-computerinfo)\b"), 1,
     "系统/网络环境侦察"),
    # ---- 免杀 / EDR 规避行为特征（针对现代免杀 Loader 的防御反制） ----
    ("SBX-AmsiTamper",
     re.compile(r"(?i)(amsiinitfailed|amsiscanbuffer|"
                r"system\.management\.automation\.amsiutils|"
                r"patch\s+(the\s+)?amsi|amsi\s+patch)"), 3,
     "篡改/绕过 AMSI 反恶意软件扫描接口"),
    ("SBX-EtwTamper",
     re.compile(r"(?i)(etweventwrite|patch\s+(the\s+)?etw|etw\s+patch)"), 2,
     "篡改 ETW 遥测以规避 EDR 检测"),
    ("SBX-Direct-Syscall",
     re.compile(r"(?i)(hellsgate|halo'?s?\s*gate|tartarus'?s?\s*gate|"
                r"syswhispers|direct\s+syscall|syscall\s+stub|"
                r"ssn\s+resolv)"), 2,
     "直接系统调用 / SSN 动态解析（绕过用户态 Hook）"),
    ("SBX-Shellcode-Decode",
     re.compile(r"(?i)(uuidfromstring|rtlipv4stringtoaddress|"
                r"rtlipv6stringtoaddress|rtlethernetstringtoaddress)"), 2,
     "Shellcode 编码伪装解码（UUID/IP/MACfuscation）"),
    ("SBX-Unhook",
     re.compile(r"(?i)(unhook|knowndlls.{0,6}ntdll|"
                r"(re-?map|refresh).{0,12}ntdll)"), 2,
     "解钩/重映射 ntdll（规避用户态 Hook）"),
    ("SBX-Memory-Exec",
     re.compile(r"(?i)(virtualalloc(ex)?|virtualprotect|writeprocessmemory|"
                r"ntmapviewofsection|createthread|ntcreatethreadex|"
                r"queueuserapc|rtlcreateuserthread)"), 1,
     "内存分配/写入/线程执行原语"),
    ("SBX-AntiSandbox",
     re.compile(r"(?i)(isdebuggerpresent|checkremotedebuggerpresent|"
                r"ntqueryinformationprocess|sandboxie|vboxservice|"
                r"vmtoolsd|vmwareuser|cuckoo\s*sandbox|"
                r"1234567\.txt|\brdtsc\b|"
                r"start-sleep\s+(-m\s+)?[6-9]\d{3,}|\bsleep\s*\(\s*[6-9]\d{3,}\s*\))"), 1,
     "反沙箱/反调试环境探测（含 drop 探针标记、长延时拖垮沙箱）"),
    ("SBX-Fake-Signature",
     re.compile(r"(?i)(signtool\s+sign|makecert\b|certutil\s+-{1,2}sign|"
                r"fake\s*sign|forge.{0,12}(cert|sign)|"
                r"self-?signed.{0,24}(cert|exe|driver)|"
                r"spoof.{0,12}(sign|cert))"), 2,
     "签名伪造/自签名伪装可信程序"),
]

# 行为组合加分：单一特征危害有限，组合出现时危害倍增
COMBO_RULES = [
    (frozenset({"SBX-Remote-Download", "SBX-Dynamic-Exec"}), 2,
     "下载内容 + 动态执行 = 典型无文件载荷投递链"),
    # ---- 免杀加载链组合 ----
    (frozenset({"SBX-Shellcode-Decode", "SBX-Memory-Exec"}), 2,
     "编码伪装 Shellcode + 内存执行 = 经典免杀加载链"),
    (frozenset({"SBX-Direct-Syscall", "SBX-Memory-Exec"}), 2,
     "直接系统调用 + 内存执行 = EDR 规避型加载链"),
    (frozenset({"SBX-AmsiTamper", "SBX-Remote-Download"}), 2,
     "绕过 AMSI + 下载执行 = 无文件投递反制链"),
    (frozenset({"SBX-AntiSandbox", "SBX-Memory-Exec"}), 1,
     "反沙箱探测 + 内存执行 = 环境规避型 Loader"),
    (frozenset({"SBX-AntiSandbox", "SBX-Direct-Syscall"}), 2,
     "反沙箱探测 + 直接系统调用 = 高规避性免杀 Loader"),
    (frozenset({"SBX-Fake-Signature", "SBX-Memory-Exec"}), 2,
     "签名伪装 + 内存执行 = 伪装可信的免杀投递链"),
]

# oletools 提取出的宏代码会与文件文本合并分析
OFFICE_SUFFIXES = {".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt"}
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _read_text(data):
    for enc in ("utf-8-sig", "utf-16"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return data.decode("latin-1")


def text_hits(text):
    """对一段文本应用全部行为规则，返回命中列表（不含组合与评分）。

    供解混淆/模拟执行等还原层复扫使用。
    """
    hits = []
    for name, rx, weight, desc in RULES:
        m = rx.search(text)
        if m:
            hits.append({"name": name, "weight": weight, "desc": desc,
                         "sample": m.group(0)[:60]})
    return hits


def analyze(path):
    """分析单个文件，返回 {path, score, verdict, hits, notes}。"""
    path = Path(path)
    result = {"path": str(path), "score": 0, "verdict": "清洁",
              "hits": [], "notes": []}
    try:
        data = path.read_bytes()
    except OSError as exc:
        result["verdict"] = "错误"
        result["notes"].append(f"无法读取: {exc}")
        return result

    text = _read_text(data)

    if data[:8] == OLE_MAGIC or path.suffix.lower() in OFFICE_SUFFIXES:
        if HAS_OLETOOLS:
            try:
                vp = VBA_Parser(str(path))
                if vp.detect_vba_macros():
                    chunks = [c[3] for c in vp.extract_macros() if c[3]]
                    text += "\n" + "\n".join(chunks)
                    result["notes"].append("检测到 VBA 宏，宏代码已合并分析")
                vp.close()
            except Exception as exc:
                result["notes"].append(f"宏解析失败: {exc}")
        else:
            result["notes"].append("Office 文档：未安装 oletools，跳过宏提取"
                                   "（pip install oletools 可启用）")

    hits = text_hits(text)
    names = {h["name"] for h in hits}
    result["hits"] = hits

    score = sum(h["weight"] for h in result["hits"])
    for combo_names, bonus, desc in COMBO_RULES:
        if combo_names <= names:
            score += bonus
            result["hits"].append({"name": "SBX-Combo", "weight": bonus,
                                   "desc": desc, "sample": ""})

    result["score"] = score
    result["verdict"] = "恶意" if score >= 4 else ("可疑" if score >= 2 else "清洁")
    return result


def format_report(result):
    lines = [f"行为分析: {result['path']}",
             f"判定: {result['verdict']}（行为评分 {result['score']}）"]
    for h in result["hits"]:
        line = f"  [{h['weight']}] {h['name']} — {h['desc']}"
        if h["sample"]:
            line += f"  样本: {h['sample']}"
        lines.append(line)
    for n in result["notes"]:
        lines.append(f"  (i) {n}")
    if not result["hits"]:
        lines.append("  未发现可疑行为特征")
    return "\n".join(lines)
