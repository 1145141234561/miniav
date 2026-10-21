r"""迭代式载荷解混淆引擎——针对"变量名/控制流混淆"的受限动态分析层。

原理：混淆改变的是表达方式（变量名、控制流、字符串包装），但投递的
载荷必然经过可逆变换（base64/hex/转义/字符数组/压缩/单字节 XOR）才能
被 Loader 还原。本引擎把这些纯数据变换逐层折叠回原始载荷，交由既有
规则引擎（YARA / 模式 / 行为正则）复扫——变量名混淆失效（还原后无变量），
控制流混淆失效（还原的是数据不是逻辑）。

安全约束（沿用项目红线：绝不执行样本）：
- 只做确定性纯函数变换（解码/解压/异或），无 eval、无指令执行、无副作用
- 全程预算控制：层数 ≤4、候选总数 ≤24、单层输出 ≤4MB、输入 ≤2MB；
  解压流带尺寸上限，防解压炸弹
"""

import base64
import hashlib
import re
import zlib

MAX_LAYERS = 4
MAX_CANDIDATES = 24
MAX_LAYER_OUT = 4 * 1024 * 1024
MAX_INPUT = 2 * 1024 * 1024

RE_B64 = re.compile(rb"[A-Za-z0-9+/]{64,}={0,2}")
RE_HEX = re.compile(rb"(?:[0-9a-fA-F]{2}){32,}")
RE_ESC = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
RE_CHARARRAY = re.compile(
    r"\[char\[\]\]\s*\(([\d\s,]{8,})\)"          # PS: [char[]](104,101,...)
    r"|fromCharCode\(([\d\s,]{8,})\)", re.I)     # JS: String.fromCharCode(...)

# 还原内容里值得关注的明文标记（用于 XOR 爆破评分与"可疑还原"判定）
_EXEC_MARKERS = (b"Invoke-Expression", b"VirtualAlloc", b"CreateRemoteThread",
                 b"WriteProcessMemory", b"powershell", b"cmd.exe /",
                 b"fromCharCode", b"AMSI")
# 小写版：XOR 评分与还原判定都在 lowered 缓冲上做 substring 匹配
_EXEC_MARKERS_LC = tuple(m.lower() for m in _EXEC_MARKERS)

_ZLIB_HEADS = (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")


def _printable_ratio(b):
    if not b:
        return 0.0
    printable = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return printable / len(b)


def _looks_interesting(b):
    """还原候选是否有分析价值：可打印 / MZ / 高价值明文标记。"""
    if len(b) < 16:
        return False
    if b[:2] == b"MZ" or b"\x1f\x8b" == b[:2]:
        return True
    if any(m in b.lower() for m in _EXEC_MARKERS_LC):
        return True
    return _printable_ratio(b[:8192]) > 0.85


def _try_deflate(data):
    """在二进制中寻找 zlib/gzip/raw-deflate 流并解压（带预算上限）。"""
    outs = []
    for h in _ZLIB_HEADS:
        start = 0
        while True:
            i = data.find(h, start)
            if i < 0:
                break
            start = i + 1
            try:
                d = zlib.decompressobj()
                out = d.decompress(data[i:], MAX_LAYER_OUT + 1)
                if len(out) > MAX_LAYER_OUT:
                    raise ValueError("decompress budget exceeded")
                if len(out) >= 32 and _looks_interesting(out):
                    outs.append(out)
                    break  # 每个头部位置取首个成功流即可
            except (zlib.error, ValueError):
                continue
    if data[:2] == b"\x1f\x8b":  # gzip 整体流
        try:
            outs.append(zlib.decompress(data, wbits=47, bufsize=MAX_LAYER_OUT + 1)
                        [:MAX_LAYER_OUT])
        except (zlib.error, ValueError, OSError):
            pass
    return outs


def _try_xor(data):
    """单字节 XOR 爆破（常见 shellcode/字符串混淆），按标记命中评分。

    只在前 64KB 上用 translate 表（C 速度）评分，命中后才对全量
    做一次异或——单文件开销毫秒级，可安全用于全量扫描。

    评分以标记命中为主、可打印比例为辅：纯 printable 在 ASCII 文本上
    大量误key并列（±0x20 区间内近半 key 都 >0.9），必须让标记分
    压过 printable 分才能稳定选中正确 key。
    """
    if len(data) < 256:
        return []
    window = data[:65536]
    best_key, best_score = 0, 0
    for key in range(1, 256):
        table = bytes(i ^ key for i in range(256))
        dec = window.translate(table).lower()
        score = 0
        for m in _EXEC_MARKERS_LC:
            if m in dec:
                score += 2
        if dec[:2] == b"mz":
            score += 2
        if _printable_ratio(dec[:4096]) > 0.9:
            score += 1
        if score > best_score:
            best_key, best_score = key, score
    if best_key and best_score >= 1:
        table = bytes(i ^ best_key for i in range(256))
        return [data.translate(table)]
    return []


def _decode_chararrays(text):
    """PS [char[]](...) / JS String.fromCharCode(...) → 明文。"""
    outs = []
    for m in RE_CHARARRAY.finditer(text):
        nums_raw = m.group(1) or m.group(2)
        try:
            nums = [int(x) for x in re.split(r"[\s,]+", nums_raw.strip()) if x]
        except ValueError:
            continue
        if not (8 <= len(nums) <= 65536):
            continue
        try:
            chars = []
            for n in nums:
                if not (9 <= n <= 0x10FFFF):
                    raise ValueError
                chars.append(chr(n))
        except ValueError:
            continue
        outs.append("".join(chars).encode("utf-8", "ignore"))
    return outs


_STRUCT_KEYS = (b"set ", b"call ", b"sub ", b"function", b"if ", b"then",
                b"end if", b"next", b"loop", b"dim ", b"wscript", b"createobject")


def _try_line_reverse(data):
    """整行字符反转混淆检测（暴风一号 Storm-1 型）。

    所有标识符以反转形态存在于原文，明文特征锚全部失效。
    判据：反转后脚本结构词命中数 > 原文 2 倍且 ≥3，才采纳还原视图——
    正常脚本反转后结构词必然骤减，不会误触发。
    """
    if len(data) < 64 or b"\x00" in data[:4096]:
        return None
    text = data.decode("utf-8", "ignore")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 4:
        return None
    rev = [ln[::-1] for ln in lines]

    def _score(ls):
        lc = [ln.lower().encode("ascii", "ignore") for ln in ls]
        return sum(1 for ln in lc for k in _STRUCT_KEYS if k in ln)

    base, rs = _score(lines), _score(rev)
    if rs > base * 2 and rs >= 3:
        return "\n".join(ln[::-1] for ln in text.splitlines()).encode("utf-8", "ignore")
    return None


def _layer_candidates(data):
    """对一层输入产出所有还原候选 [(变换名, bytes)]。"""
    cands = []
    text = None
    for m in RE_B64.finditer(data):
        blob = m.group(0)
        if len(blob) % 4:
            blob += b"=" * (4 - len(blob) % 4)
        try:
            dec = base64.b64decode(blob, validate=False)
        except Exception:
            continue
        if len(dec) >= 32:
            cands.append(("base64", dec))
    for m in RE_HEX.finditer(data):
        try:
            dec = bytes.fromhex(m.group(0).decode("ascii", "ignore"))
        except ValueError:
            continue
        if len(dec) >= 32:
            cands.append(("hex", dec))
    if text is None:
        try:
            text = data.decode("utf-8", "ignore")
        except Exception:
            text = ""
    for m in RE_ESC.finditer(text):
        try:
            dec = bytes.fromhex(re.sub(r"\\x", "", m.group(0)))
        except ValueError:
            continue
        if len(dec) >= 8:
            cands.append(("hex-escape", dec))
    for dec in _decode_chararrays(text):
        if len(dec) >= 8:
            cands.append(("char-array", dec))
    for dec in _try_deflate(data):
        cands.append(("deflate", dec))
    for dec in _try_xor(data):
        cands.append(("xor-single-byte", dec))
    rev = _try_line_reverse(data)
    if rev:
        cands.append(("line-reverse", rev))
    return cands


def reveal(data):
    """迭代折叠还原载荷，返回 [(chain, bytes)]。

    chain 形如 "base64→deflate"；广度优先、sha256 去重防环。
    只有"值得关注"的层进入返回列表，但所有候选都继续折叠——
    中间层（如压缩字节流）本身看着像噪声，必须穿透才能还原内层。
    预算：层数 ≤4、处理候选 ≤48、报告候选 ≤24、单层输出 ≤4MB。
    """
    if len(data) > MAX_INPUT:
        return []
    seen = {hashlib.sha256(data).hexdigest()}
    out, queue, processed = [], [("", data)], 0
    while queue and processed < 48 and len(out) < MAX_CANDIDATES:
        chain, blob = queue.pop(0)
        processed += 1
        depth = chain.count("→") + 1 if chain else 0
        if depth >= MAX_LAYERS:
            continue
        for name, dec in _layer_candidates(blob):
            if len(dec) > MAX_LAYER_OUT:
                continue
            h = hashlib.sha256(dec).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            nxt = f"{chain}→{name}" if chain else name
            if _looks_interesting(dec):
                out.append((nxt, dec))
            if len(out) >= MAX_CANDIDATES:
                break
            queue.append((nxt, dec))
    return out
