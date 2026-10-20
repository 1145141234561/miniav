// Windows 脚本类威胁：PowerShell 投递 / LOLBin 远程加载 / 编码载荷

rule PS_Hidden_Encoded_Command {
    meta:
        description = "PowerShell 隐藏窗口 + 大段编码命令（常见投递手法）"
        level = "high"
    strings:
        $hidden = /-(w|windowstyle)\s+hidden/ nocase
        $enc = /-(e|ec|encodedcommand)\s+[\w+\/=]{40,}/ nocase
    condition:
        all of them and filesize < 5MB
}

rule PS_Cradle_Invoke_Download {
    meta:
        description = "PowerShell 下载远程内容并内存执行（cradle）"
        level = "high"
    strings:
        $dl1 = { 44 6F 77 6E 6C 6F 61 64 53 74 72 69 6E 67 }        // DownloadString
        $dl2 = { 44 6F 77 6E 6C 6F 61 64 46 69 6C 65 }              // DownloadFile
        $dl3 = { 49 6E 76 6F 6B 65 2D 57 65 62 52 65 71 75 65 73 74 } // Invoke-WebRequest
        $iex1 = { 49 6E 76 6F 6B 65 2D 45 78 70 72 65 73 73 69 6F 6E } // Invoke-Expression
        $iex2 = { 49 45 58 }                                          // IEX
    condition:
        1 of ($dl*) and 1 of ($iex*) and filesize < 5MB
}

rule LOLBin_Remote_Load {
    meta:
        description = "mshta/rundll32/regsvr32/schtasks 加载远程载荷"
        level = "high"
    strings:
        $mshta = /mshta\s+https?:\/\// nocase
        $rundll = /rundll32\s+javascript/ nocase
        $regsvr = /regsvr32\s+\/i\s*:https?:\/\// nocase
        $schtasks = /schtasks\s+\/create[^\r\n]{0,120}https?:\/\// nocase
    condition:
        any of them and filesize < 5MB
}

rule Base64_Blob_With_Exec {
    meta:
        description = "大段 base64 与动态执行调用并存（编码载荷迹象）"
        level = "medium"
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
        $exec = /(invoke-expression|\biex\b|\beval\s*\(|execscript|atob\s*\()/ nocase
    condition:
        all of them and filesize < 5MB
}
