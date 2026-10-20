/*
 * BYOVD（Bring Your Own Vulnerable Driver）特征规则
 * 检测公开已知、常被攻击者加载利用的漏洞内核驱动。
 * 全部规则带 MZ 门：仅命中真实 PE，避免规则源文件自匹配。
 */

rule BYOVD_Dell_DBUtil
{
    meta:
        description = "Dell DBUtil 漏洞驱动（CVE-2021-21551，读写内核内存）"
        level = "high"
    strings:
        $s = "DBUtil_2_" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $s
}

rule BYOVD_Gigabyte_gdrv
{
    meta:
        description = "GIGABYTE/MSI gdrv 漏洞驱动（CVE-2018-19320，任意物理内存读写）"
        level = "high"
    strings:
        $s = { 67 00 64 00 72 00 76 00 }
    condition:
        uint16(0) == 0x5A4D and $s
}

rule BYOVD_MSIAfterburner_RTCore64
{
    meta:
        description = "MSI Afterburner RTCore64 漏洞驱动（任意内核内存读写）"
        level = "high"
    strings:
        $s = "RTCore64" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $s
}

rule BYOVD_ASRock_AsrDrv
{
    meta:
        description = "ASRock AsrDrv 漏洞驱动（CVE-2020-15368，ring0 提权）"
        level = "high"
    strings:
        $s = "AsrDrv" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $s
}

rule BYOVD_MsIo
{
    meta:
        description = "MSI MsIo64 漏洞驱动（内核内存任意读写）"
        level = "high"
    strings:
        $s = { 4D 00 73 00 49 00 6F 00 }
    condition:
        uint16(0) == 0x5A4D and $s
}

rule BYOVD_WinIo
{
    meta:
        description = "WinIo 直接端口/物理内存访问驱动（常被 BYOVD 滥用）"
        level = "high"
    strings:
        $s = "WinIo" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $s
}

rule BYOVD_InpOutX64
{
    meta:
        description = "InpOut32/64 端口访问驱动（常被 BYOVD 滥用）"
        level = "high"
    strings:
        $s = "inpoutx64" ascii nocase
    condition:
        uint16(0) == 0x5A4D and $s
}
