# start.ps1 — netryx_demo 一键启动(薄壳: 定位目录 -> 中文欢迎 -> 调 scripts/launch.py -> 透传退出码)
$ErrorActionPreference = "Stop"

# 1) 定位自身目录,并确保输出编码为 UTF-8(与 chcp 65001 配套,防中文乱码)
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}

# 2) 环境中检查: python 是否存在
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "[错误] 未找到 python,请先安装 Python 3.8+(安装时勾选 Add Python to PATH)" -ForegroundColor Red
    exit 2
}

# 3) 中文欢迎(手机访问地址由 launch.py 的环境检测报告输出,此处不再计算)
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " netryx_demo - 局域网设备与连接管理" -ForegroundColor Cyan
Write-Host " 正在环境自检并启动服务;手机访问地址见下方检测报告" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# 4) 调主流程脚本,参数原样透传(--port/--host/--data-dir/--check-only)
$launchScript = Join-Path $root "scripts\launch.py"
if (-not (Test-Path $launchScript)) {
    Write-Host "[错误] 找不到 $launchScript,请确认项目文件完整" -ForegroundColor Red
    exit 2
}
& $python.Source -X utf8 $launchScript @args
$exitCode = $LASTEXITCODE
if ($null -eq $exitCode) { $exitCode = 1 }

# 5) 非零退出时补一行指引,然后透传退出码
if ($exitCode -ne 0) {
    Write-Host ""
    Write-Host "[提示] 启动未成功(退出码 $exitCode)。常见原因: 端口被占用(--port 换端口)、" -ForegroundColor Yellow
    Write-Host "       数据目录不可写、或 Python 版本过低;请按上方报告中的修复指引处理。" -ForegroundColor Yellow
}
exit $exitCode
