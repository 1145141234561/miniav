// 免杀 / EDR 规避技术静态特征（防御侧反制）
// 覆盖常见免杀 Loader 构建手法：shellcode 编码伪装（UUID/IP(v4/v6)/MACfuscation）、
// 十六进制转义字节数组、直接系统调用（HellsGate/HalosGate/SysWhispers 族）、
// MSF/CS 风格 shellcode 前导、AMSI/ETW 篡改、ntdll 解钩、VEH 内存加载。
// 已知误报来源：ntdll/win32u 等系统 DLL 含大量 syscall 桩；
// System.Management.Automation.dll 自身含 amsiInitFailed 字段名；
// 安全工具（Process Hacker 等）含 Nt* API 名；
// 链接 OpenSSL 的正常程序含 AES S-box（已用内存执行组合条件压制）；
// 十六进制导出工具（xxd/hexdump 输出）含少量 \xNN 转义。
// 规则文本刻意用正则形式书写关键字符串，避免匹配规则文件自身。

rule Evasion_UUID_Shellcode {
    meta:
        description = "Shellcode 伪装为 UUID 数组（UUIDfuscation，免杀 Loader 常用）"
        level = "medium"
    strings:
        $uuid = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/
        $c1 = "UuidFromString" ascii nocase
        $c2 = "UuidToString" ascii nocase
    condition:
        #uuid * 1024 > filesize or (any of ($c*) and #uuid > 4)
}

rule Evasion_IPfuscation {
    meta:
        description = "Shellcode 伪装为 IPv4 地址数组（IPfuscation）"
        level = "medium"
    strings:
        $ip = /\b(\d{1,3}\.){3}\d{1,3}\b/
        $c1 = "RtlIpv4StringToAddress" ascii nocase
        $c2 = "inet_addr" ascii nocase
    condition:
        #ip > 40 or (any of ($c*) and #ip > 12)
}

rule Evasion_MAC_Shellcode {
    meta:
        description = "Shellcode 伪装为 MAC 地址（MACfuscation，RtlEthernet 转换执行）"
        level = "high"
    strings:
        $c1 = /RtlEthernet\s*StringToAddress/ nocase
    condition:
        $c1
}

rule Evasion_Direct_Syscall_Framework {
    meta:
        description = "直接系统调用/SSN 动态解析框架特征（HellsGate/HalosGate/Tartarus/SysWhispers 族）"
        level = "high"
    strings:
        $g1 = /(Hells?|Halos?|Tartarus'?s?)\s*Gates?/ nocase
        $g2 = /Sys\s*Whispers/ nocase
    condition:
        any of ($g*)
}

rule Evasion_Syscall_Stubs {
    meta:
        description = "PE 内大量 syscall;ret 桩且伴随 VEH/注入 API（直接系统调用 Loader；ntdll/win32u 为已知误报）"
        level = "medium"
    strings:
        $stub = { 0F 05 C3 }
        $v1 = "AddVectoredExceptionHandler" ascii nocase
        $i1 = "NtCreateThreadEx" ascii nocase
        $i2 = "WriteProcessMemory" ascii nocase
    condition:
        uint16(0) == 0x5A4D and #stub > 6 and 1 of ($v1, $i1, $i2)
}

rule Evasion_AMSI_Patch {
    meta:
        description = "AMSI 防护篡改载荷（amsiInitFailed 置位 / AmsiUtils 补丁）"
        level = "high"
    strings:
        $a1 = /amsi\s*Init\s*Failed/ nocase
        $a2 = /Amsi\s*Utils/ nocase
        $b1 = /System\.Management\.Automation/ nocase
        $p1 = /patch/ nocase
        $p2 = "VirtualProtect" ascii nocase
    condition:
        $a1 or ($a2 and $b1) or (1 of ($a*) and any of ($p*))
}

rule Evasion_ETW_Patch {
    meta:
        description = "ETW 遥测篡改（EtwEventWrite + mov eax,0;ret 内联补丁模式）"
        level = "high"
    strings:
        $e1 = "EtwEventWrite" ascii nocase
        $patch = { B8 00 00 00 00 C3 }
    condition:
        uint16(0) == 0x5A4D and $e1 and $patch
}

rule Evasion_Unhook_Ntdll {
    meta:
        description = "ntdll 解钩/重映射（规避 EDR 用户态 Hook）"
        level = "medium"
    strings:
        $u1 = "KnownDlls\\ntdll.dll" ascii nocase
        $u2 = "ntdll.dll" ascii nocase wide
        $m1 = "NtMapViewOfSection" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($u1 or all of ($u2, $m1))
}

rule Evasion_VEH_Memory_Loader {
    meta:
        description = "VEH 异常驱动的内存免杀加载（VEH + 内存翻转执行）"
        level = "medium"
    strings:
        $v1 = "AddVectoredExceptionHandler" ascii nocase
        $m1 = "VirtualProtect" ascii nocase
        $m2 = "VirtualAlloc" ascii nocase
    condition:
        uint16(0) == 0x5A4D and all of ($v1, $m1, $m2)
}

rule Evasion_IPv6fuscation {
    meta:
        description = "Shellcode 伪装为 IPv6 地址数组（IPfuscation IPv6 变体，RtlIpv6 转换执行）"
        level = "medium"
    strings:
        $ip6 = /([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/
        $c1 = /RtlIpv6\s*StringToAddress/ nocase
    condition:
        #ip6 > 40 or (any of ($c*) and #ip6 > 4)
}

rule Evasion_Hex_Escape_Shellcode {
    meta:
        description = "十六进制转义字节数组形式的 Shellcode/加密载荷（大量 \\xNN 连续转义序列）"
        level = "medium"
    strings:
        $esc = /\\x[0-9a-fA-F]{2}/
    condition:
        #esc > 300
}

rule Evasion_Shellcode_Prologue {
    meta:
        description = "PE 内嵌 MSF/CS 风格 shellcode 前导（cld 入口桩）+ 内存执行 API"
        level = "medium"
    strings:
        $p1 = { FC 48 83 E4 F0 }        // x64: cld; and rsp, 0xF0
        $p2 = { FC E8 89 00 00 00 }     // x86: cld; call 下一条指令附近
        $e1 = "VirtualAlloc" ascii nocase
        $e2 = "VirtualProtect" ascii nocase
        $e3 = "CreateThread" ascii nocase
    condition:
        uint16(0) == 0x5A4D and any of ($p*) and 1 of ($e*)
}
