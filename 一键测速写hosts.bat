@echo off
REM 一键：跑 CloudflareSpeedTest 测速 -> 把最优 IP 写入 hosts
chcp 65001 >nul
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] 需要管理员权限，正在请求提权...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo ================================
echo   CF 优选 IP 一键写入 hosts
echo ================================
echo.
python "%~dp0cf_hosts.py" --domain bgacn.com --run --top 2
echo.
ipconfig /flushdns >nul 2>&1
echo [*] DNS 已刷新。浏览器关掉重开即可。
echo.
pause
