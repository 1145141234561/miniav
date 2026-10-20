// Webshell 静态特征（PHP / JSP / ASP）
// 书写约定：正则中的 ( ) . $ 均转义，避免规则文件被自家规则命中

rule PHP_Eval_Request_Superglobal {
    meta:
        description = "PHP 直接执行请求参数（典型 webshell）"
        level = "high"
    strings:
        $eval = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/ nocase
        $assert = /assert\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $preg = /preg_replace\s*\(\s*['"]\/.*\/e['"]/ nocase
    condition:
        any of them and filesize < 1MB
}

rule PHP_Command_Exec_Request {
    meta:
        description = "PHP 命令执行函数直接作用于请求参数"
        level = "high"
    strings:
        $sys = /system\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $passthru = /passthru\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $shellexec = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $popen = /popen\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
    condition:
        any of them and filesize < 1MB
}

rule PHP_Decode_Request_Exec {
    meta:
        description = "PHP 解码请求输入后动态执行（变形 webshell）"
        level = "high"
    strings:
        $a = /base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $b = /(eval|assert)\s*\(\s*base64_decode/ nocase
    condition:
        any of them and filesize < 1MB
}

rule JSP_Runtime_Exec_Param {
    meta:
        description = "JSP 将请求参数传入 Runtime.exec（webshell）"
        level = "high"
    strings:
        $a = /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*request\s*\.\s*getParameter/ nocase
        $b = /ProcessBuilder\s*\(\s*request\s*\.\s*getParameter/ nocase
    condition:
        any of them and filesize < 1MB
}

rule ASP_Execute_Request {
    meta:
        description = "ASP/ASPX 执行请求内容"
        level = "high"
    strings:
        $a = /eval\s*\(\s*request\s*\.\s*(item|form|querystring)/ nocase ascii wide
        $b = /execute\s*\(\s*request\s*\.\s*(item|form|querystring)/ nocase ascii wide
    condition:
        any of them and filesize < 1MB
}
