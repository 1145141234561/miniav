r"""Unicorn 受限模拟——针对"控制流混淆"的动态检测层（不落地执行）。

原理：控制流混淆（花指令/不透明谓词/调度器扁平化）让静态扫描看不到
运行时才还原的载荷（解密字符串/拼接 shellcode）。把样本代码放进
Unicorn 纯 CPU 模拟器执行有限步，然后扫描模拟内存中"运行时出现"的内容，
再用既有规则引擎复扫。

安全约束（沿用项目红线：绝不执行样本）：
- Unicorn 是纯内存状态机，不执行任何系统调用、不触碰宿主进程/文件/网络；
  非法内存访问与 HLT 直接终止模拟——样本对宿主机零风险
- 预算：指令数 ≤100K、内存映射固定 8MB，异常即停
- unicorn 为可选依赖，缺失时优雅降级（模拟层整体跳过）
"""

try:
    from unicorn import (
        Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_INVALID, UC_ERR_EXCEPTION,
        x86_const as _x86,
    )
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False

MAX_STEPS = 100_000
CODE_BASE = 0x400000
CODE_SIZE = 4 * 1024 * 1024      # 样本映射区上限
STACK_BASE = 0x20000000
STACK_SIZE = 1 * 1024 * 1024

MIN_REVEAL = 8                    # 还原片段最小长度


def _map_image(uc, data):
    """平坦映射样本到 CODE 区，返回入口地址。

    PE 的 RVA 与文件偏移不作节对齐换算（模拟的是受限快照而非真实加载），
    入口 = CODE_BASE + AddressOfEntryPoint；非 PE/解析失败取文件头。
    """
    uc.mem_map(CODE_BASE, CODE_SIZE)
    uc.mem_write(CODE_BASE, data[:CODE_SIZE])
    entry_rva = 0
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    except Exception:
        pass
    return CODE_BASE + entry_rva


def emulate(data, max_steps=MAX_STEPS):
    """模拟执行样本代码，返回运行时内存中"值得复扫"的还原片段列表。

    返回 [(来源描述, bytes)]。非法内存访问 / HLT / 非法指令 / 超步数
    都视为模拟正常终止，不向外传播。
    """
    if not HAS_UNICORN or not data or data[:2] != b"MZ":
        return []
    try:
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        entry = _map_image(uc, data)
        uc.mem_map(STACK_BASE, STACK_SIZE)
        uc.reg_write(_x86.UC_X86_REG_RSP, STACK_BASE + STACK_SIZE // 2)

        def _on_bad_mem(uc_, access, address, size, value, user_data):
            uc_.emu_stop()
            return False

        uc.hook_add(UC_HOOK_MEM_INVALID, _on_bad_mem)
        try:
            uc.emu_start(entry, 0, count=max_steps)
        except Exception:
            pass  # HLT / 非法指令 / 非法内存都属正常终止

        out, seen = [], set()
        for desc, begin, end in (("code", CODE_BASE, CODE_BASE + CODE_SIZE),
                                 ("stack", STACK_BASE, STACK_BASE + STACK_SIZE)):
            try:
                mem = bytes(uc.mem_read(begin, end - begin))
            except Exception:
                continue
            for frag in _extract_reveals(mem):
                h = hash(frag)
                if h not in seen:
                    seen.add(h)
                    out.append((desc, frag))
        return out
    except Exception:
        return []


def _extract_reveals(mem):
    """从模拟内存提取含可执行/行为标记的 ASCII 片段。"""
    import re as _re
    out = []
    for m in _re.finditer(rb"[\x20-\x7e]{16,}", mem):
        frag = m.group(0)
        if any(k in frag.lower() for k in
               (b"invoke-expression", b"virtualalloc", b"createthread",
                b"writeprocessmemory", b"cmd.exe", b"powershell", b"http://",
                b"https://")):
            out.append(frag)
    return out
