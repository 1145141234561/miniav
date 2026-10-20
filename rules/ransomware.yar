/*
    勒索病毒家族特征（仅收录高置信公开 IOC）
    字符串统一用 \s* 断字正则书写，避免规则文件自身被扫描命中；
    命中需人工研判，安全研究/报告类文档可加白。
    门条件：PE 加 MZ 门；勒索信/脚本等文本用 filesize < 4MB。
*/

rule Ransomware_GandCrab
{
    meta:
        family = "GandCrab"
        level = "high"
        source = "ransomware"
    strings:
        $name = /GAND\s*CRAB/i
        $ext = /\.CR\s*AB/i
    condition:
        (uint16(0) == 0x5A4D or filesize < 4MB) and 2 of ($*)
}

rule Ransomware_Locky
{
    meta:
        family = "Locky"
        level = "high"
        source = "ransomware"
    strings:
        $name = /LOCK\s*Y/i
        $ext = /\.loc\s*ky/i
    condition:
        (uint16(0) == 0x5A4D or filesize < 4MB) and 2 of ($*)
}

rule Ransomware_Ryuk
{
    meta:
        family = "Ryuk"
        level = "high"
        source = "ransomware"
    strings:
        $name = /RY\s*UK/i
        $note = /Ryuk\s*Read\s*Me/i
    condition:
        (uint16(0) == 0x5A4D or filesize < 4MB) and 2 of ($*)
}
