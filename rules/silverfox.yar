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
