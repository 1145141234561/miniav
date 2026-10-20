// 打包器/安装器识别（信息提示类：加壳不必然恶意，供人工研判参考）

rule UPX_Packed {
    meta:
        description = "UPX 加壳 PE"
        level = "medium"
    strings:
        $u = "UPX!"
    condition:
        uint16(0) == 0x5A4D and $u
}

rule PyInstaller_Bundle {
    meta:
        description = "PyInstaller 打包的程序"
        level = "low"
    strings:
        $m = { 4D 45 49 0C 0B }
    condition:
        uint16(0) == 0x5A4D and $m
}

rule AutoIt_Script_Bundle {
    meta:
        description = "AutoIt 打包脚本（常被恶意利用，需结合行为判断）"
        level = "medium"
    strings:
        $a1 = "AU3!EA05"
        $a2 = "AU3!EA06"
    condition:
        uint16(0) == 0x5A4D and 1 of ($a*)
}

rule Nullsoft_Installer {
    meta:
        description = "Nullsoft (NSIS) 安装包"
        level = "low"
    strings:
        $a = "NullsoftInst"
    condition:
        uint16(0) == 0x5A4D and $a
}
