/*
    银狐（Silver Fox）家族特征——高置信公开 IOC
    MZ 门保证仅命中 PE 载荷（SFX/远控/下载器），安全研究报告类
    文本不误报；命中需人工研判。
*/

rule SilverFox_Ghost_Family
{
    meta:
        family = "Gh0st/SilverFox"
        level = "high"
        source = "silverfox"
    strings:
        $gh0st = "gh0st" ascii nocase
        $wolf = "大灰狼" wide ascii
        $valley = "valleyrat" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($*)
}

/*
    2026-10 实战样本（仿冒 W.P.S.50.513.exe，PyInstaller 3.8 一体式释放器）：
    CArchive TOC 主条目名 kb_out_W.P.S.50.513（压缩原件明文可扫），
    源码生成器固定变量名 hex_string_1/2、RunExeThread、释放目录 C:\AweSun
    （向日葵远控被滥用通道，位于 zlib 压缩的 marshal 内——解压 blob/
    内存转储场景命中）。2 of 控制防对正常 PyInstaller 程序误报。
    IOC 来自真实样本静态分析，置信度高。
*/
rule SilverFox_KbOut_Dropper
{
    meta:
        family = "SilverFox/KbOut"
        level = "high"
        source = "silverfox"
        sample_sha256 = "49326e17bb648929e7d8ecf3b0accc195e04c18f7ee59e27e24d865c6ea9f7a9"
    strings:
        $t1 = "kb_out_" ascii
        $t2 = "W.P.S." ascii
        $v1 = "hex_string_1" ascii
        $v2 = "RunExeThread" ascii
        $p1 = "C:\\AweSun" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($*)
}

/* setup.exe 恶意加载器（SafeCenter 系）：读 C:\config\pd1-4.txt 分段配置 */
rule SilverFox_SafeCenter
{
    meta:
        family = "SilverFox/SafeCenter"
        level = "high"
        source = "silverfox"
        sample_sha256 = "20f6d52d0194aa2e28e1e44f529e6d93c2ac2c23e650115d6479d67150861875"
    strings:
        $s1 = "SafeCenterController" ascii wide nocase
        $p1 = /C:\\config\\pd[1-4]\.txt/ ascii
    condition:
        uint16(0) == 0x5A4D and 1 of ($*)
}

/*
    2026-09 instapp.s.1.12 投递链（微步云沙箱判定：银狐黑产团伙）：
    instapp.s.1.12.exe → C:\Users\Public\nfJG82\ 随机名载荷 + DLL 侧加载
    （UxEnhance64.dll/XPSPLOG.dll）→ SYSTEM 计划任务写 Defender 排除项
    → C2 回连阿里云 OSS。两条规则覆盖解压后 PE 内嵌场景。
*/
rule SilverFox_InstApp_C2
{
    meta:
        family = "SilverFox/InstApp"
        level = "high"
        source = "silverfox"
        sample_sha256 = "d280bc9cbf487bec0c69fc62d4f3481a6d853315ddc424028b32604c42b0577b"
    strings:
        $d1 = "mm2027.oss-cn-hangzhou.aliyuncs.com" ascii wide nocase
        $d2 = "ybjyz0.oss-cn-beijing.aliyuncs.com" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($*)
}

/* DLL 侧加载组件名（UxEnhance64/XPSPLOG，报告类文本无 MZ 门不误报） */
rule SilverFox_Sideload_Chain
{
    meta:
        family = "SilverFox/InstApp"
        level = "medium"
        source = "silverfox"
    strings:
        $n1 = "UxEnhance64" ascii wide nocase
        $n2 = "XPSPLOG" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($*)
}

/* ==================== 多态泛化层 ====================
    设计原则：字面串（域名/目录/变量名）重编译即可替换，锚定成本最低；
    生成器指纹（模板属性）、功能性 API 组合、滥用模式在变形后仍保留。
    本层规则锚定后者，与前述字面层规则互补。 */

/*
    生成器指纹：银狐黑产安装器生成器固定的厂商属性名。
    产品名随仿冒目标变（WPS/Chrome/FinalShell...），厂商名不改。
    门 = PE 或 MSI（OLE 复合文档 magic D0CF11E0）。
*/
rule SilverFox_SpoofInstaller_Gen
{
    meta:
        family = "SilverFox/Installer-Gen"
        level = "medium"
        source = "silverfox"
        note = "变形抗性：仿冒目标可换，生成器厂商属性不变"
    strings:
        $v1 = "MonKeyDu" ascii wide nocase
        $v2 = "KingDialog" ascii wide nocase
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0xE011CFD0) and 1 of ($v*)
}

/*
    功能结构锚：线程上下文注入全套 API（挂起→改上下文→恢复 + 内存分配）。
    功能决定导入表，重编译/换壳/改串都不变；合法软件极少同时具备四件。
    命中 ProgramPolicy.exe（23MB 32 位注入器）验证。
*/
rule SilverFox_ThreadCtx_Inject
{
    meta:
        family = "SilverFox/Loader-Gen"
        level = "medium"
        source = "silverfox"
        note = "变形抗性：API 组合由功能决定，多态重编译不变"
    strings:
        $a1 = "SuspendThread" ascii
        $a2 = "SetThreadContext" ascii
        $a3 = "ResumeThread" ascii
        $a4 = "VirtualAlloc" ascii
    condition:
        uint16(0) == 0x5A4D and all of ($a*)
}

/*
    基础设施泛化：云对象存储 C2 + 投递上下文双锚。
    具体 bucket 域名随批次换，但 OSS 托管 + Public/Downloads 投递
    的组合模式不变；正常软件嵌 OSS 下载域时无投递路径伴生。
*/
rule SilverFox_OSS_C2_Gen
{
    meta:
        family = "SilverFox/Infra-Gen"
        level = "medium"
        source = "silverfox"
        note = "变形抗性：bucket 换名成本低，托管+投递组合模式成本高"
    strings:
        $oss = /oss-cn-[a-z0-9]+\.aliyuncs\.com/ ascii wide nocase
        $p1 = "Users\\Public\\" ascii wide nocase
        $p2 = "Downloads\\" ascii wide nocase
        $t1 = "kb_out_" ascii
    condition:
        uint16(0) == 0x5A4D and $oss and 1 of ($p*, $t1)
}

/*
    合法远控滥用模式：向日葵/Sunlogin + 静默执行逻辑同体。
    合法安装包本体只含品牌串、无执行编排代码；释放器同时具备
    两者——哈希随版本更新失效，模式锚持续有效。
*/
rule SilverFox_AweSun_Abuse
{
    meta:
        family = "SilverFox/RAT-Abuse"
        level = "high"
        source = "silverfox"
        note = "变形抗性：远控版本更新换哈希，滥用编排模式不变"
    strings:
        $s1 = "AweSun" ascii wide nocase
        $s2 = "SunloginClient" ascii wide nocase
        $x1 = "RunExeThread" ascii
        $x2 = /subprocess\.run|WinExec|ShellExecute/ ascii nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($s*) and 1 of ($x*)
}

/*
    投递行为泛化：公共目录释放 + 随机名可执行/持久化动词。
    随机目录名每批不同（正则泛化），「公共目录+随机 exe/schtasks」
    的行为结构不变。
*/
rule SilverFox_StageDrop_Public
{
    meta:
        family = "SilverFox/Drop-Gen"
        level = "medium"
        source = "silverfox"
        note = "变形抗性：随机名每批变，公共目录投递结构不变"
    strings:
        $p1 = "Users\\Public\\" ascii wide nocase
        $e1 = /[A-Za-z0-9]{4,10}\\[A-Za-z0-9]{3,10}\.exe/ ascii wide
        $d1 = "schtasks" ascii nocase
        $d2 = "reg add" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $p1 and 1 of ($e*, $d*)
}
