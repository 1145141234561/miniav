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
