# MiniAVProt.sys 构建脚本：优先 WDK + MSVC，无 WDK 时自动回退 mingw(TDM-GCC)
# 用法: powershell -ExecutionPolicy Bypass -File build.ps1
# 依赖: 方案A = Visual Studio 2022(C++) + WDK 10; 方案B = TDM-GCC 64
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---------- 方案 B：mingw 回退（无 WDK 时） ----------
function Build-WithMingw {
    Write-Host "[i] 未找到 WDK，回退 mingw 构建（TDM-GCC）"
    $gcc = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if (-not $gcc) { throw "既无 WDK 也无 gcc，无法构建" }
    $mingwRoot = Split-Path (Split-Path $gcc.Source)   # ...\TDM-GCC-64\bin -> TDM-GCC-64
    $ddk = Join-Path $mingwRoot 'x86_64-w64-mingw32\include\ddk'
    $oldLib = Join-Path $mingwRoot 'x86_64-w64-mingw32\lib\libntoskrnl.a'
    # mingw 自带 libntoskrnl.a 缺新导出（如 IoCreateDeviceSecure）——
    # 用 pefile 从本机 ntoskrnl.exe 生成完整 def，再 dlltool 生成导入库
    $def = Join-Path $env:TEMP 'ntoskrnl.def'
    $lib = Join-Path $env:TEMP 'libntoskrnl_full.a'
    python -c "import pefile, os; pe = pefile.PE(r'C:\Windows\System32\ntoskrnl.exe', fast_load=True); pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]); names = [s.name.decode() for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name]; open(os.path.join(os.environ['TEMP'], 'ntoskrnl.def'), 'w').write('LIBRARY ntoskrnl.exe\nEXPORTS\n' + '\n'.join(names) + '\n')"
    dlltool -m i386:x86-64 -d $def -l $lib
    & $gcc.Source -O2 -Wall -shared -nostdlib -nostartfiles `
        -DNTDDI_VERSION=0x0A000004 -D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00 `
        -o (Join-Path $here 'MiniAVProt.sys') (Join-Path $here 'MiniAVProt.c') `
        "-I$ddk" -include (Join-Path $here 'miniaav_mingw_compat.h') `
        "-Wl,--entry,DriverEntry" "-Wl,--subsystem,native" $lib
    if ($LASTEXITCODE -ne 0) { throw "mingw 构建失败" }
    Write-Host "[+] mingw 构建完成: $here\MiniAVProt.sys"
    # 用现有用户证书签名（测试模式需证书入 受信任的根/发布者）
    $cert = Get-ChildItem Cert:\CurrentUser\My | Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($cert) {
        Set-AuthenticodeSignature -FilePath (Join-Path $here 'MiniAVProt.sys') `
            -Certificate $cert -TimeStampServer 'http://timestamp.digicert.com' | Out-Null
        Write-Host "[+] 已签名: $($cert.Subject)"
    }
    return
}

# ---------- 方案 A：WDK + MSVC ----------
$kits = @("${env:ProgramFiles(x86)}\Windows Kits\10", "${env:ProgramFiles}\Windows Kits\10") |
        Where-Object { Test-Path $_ }
if (-not $kits) { throw "未找到 Windows Kits，请先安装 WDK 10: https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk" }
$kit = $kits[0]
$ver = Get-ChildItem (Join-Path $kit 'Include') -Directory |
       Where-Object { Test-Path (Join-Path $_.FullName 'km') } |
       Sort-Object Name -Descending | Select-Object -First 1
if (-not $ver) { throw "未找到 WDK 头文件（Include\*\km），请确认已安装 WDK" }
$incKm = Join-Path $ver.FullName 'km'
$incShared = Join-Path $ver.FullName 'shared'
$libKm = Join-Path (Join-Path $kit "Lib\$($ver.Name)\km\x64") ''
if (-not (Test-Path $libKm)) { throw "未找到 WDK 库目录: $libKm" }
Write-Host "[i] WDK: $($ver.FullName)"

# 2) 定位 Visual Studio（vcvars64 提供 cl/link 与 MSVC CRT 库）
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "未找到 vswhere，请安装 Visual Studio 2022" }
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
if (-not $vs) { throw "未找到带 C++ 生成工具的 Visual Studio，请安装 '使用 C++ 的桌面开发' 工作负载" }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) { throw "未找到 vcvars64.bat: $vcvars" }
Write-Host "[i] VS:  $vs"

# 3) 编译 + 链接（kernel 模式，无 CRT 依赖）
$cmd = @"
call `"$vcvars`" >nul
cl /nologo /W4 /WX /O2 /kernel /GS /D_AMD64_ /DAMD64 /D_WIN64 /DWINVER=0x0A00 /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A000004 /I"$incKm" /I"$incShared" /c `"$here\MiniAVProt.c`" /Fo"$here\MiniAVProt.obj"
if errorlevel 1 exit /b 1
link /nologo /driver /subsystem:native /entry:DriverEntry /out:"$here\MiniAVProt.sys" "$here\MiniAVProt.obj" /LIBPATH:"$libKm" ntoskrnl.lib wdmsec.lib bufferoverflowK.lib libcntpr.lib
if errorlevel 1 exit /b 1
"@
$cmd | Out-File -Encoding ascii (Join-Path $env:TEMP 'miniaav_build.bat') | Out-Null
cmd /s /c "`"%TEMP%\miniaav_build.bat`""
if ($LASTEXITCODE -ne 0) { throw "构建失败（见上方输出）" }
Remove-Item (Join-Path $env:TEMP 'miniaav_build.bat') -ErrorAction SilentlyContinue
Write-Host "[+] 构建完成: $here\MiniAVProt.sys"

# 4) 可选：用当前用户自签名证书签名（测试模式需证书入 受信任的根/发布者）
$signtool = Get-ChildItem (Join-Path $kit 'bin') -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match 'x64' } | Select-Object -First 1
$cert = Get-ChildItem Cert:\CurrentUser\My | Sort-Object NotAfter -Descending | Select-Object -First 1
if ($signtool -and $cert) {
    & $signtool.FullName sign /fd sha256 /n "$($cert.Subject)" "$here\MiniAVProt.sys"
    if ($LASTEXITCODE -eq 0) { Write-Host "[+] 已签名: $($cert.Subject)" }
    else { Write-Host "[!] 签名失败，可稍后手动 signtool sign" }
}
