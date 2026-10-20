// miniantivirus 示例 YARA 规则集
// 设计要点：$head at 0 要求文件开头命中，避免匹配本项目自身源码/文档

rule EICAR_Test_File {
    meta:
        description = "EICAR 标准杀软测试文件（行业公认自测用例，无害）"
        level = "high"
    strings:
        $head = "X5O!P%@AP"
        $tail = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $head at 0 and $tail
}

rule Demo_PowerShell_Web_Exec {
    meta:
        description = "PowerShell 通过 WebClient 下载远程内容"
        level = "medium"
    strings:
        $pat = /downloadstring\s*\(\s*['"]https?:\/\// nocase
    condition:
        $pat
}
