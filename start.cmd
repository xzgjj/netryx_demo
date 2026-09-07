@echo off
chcp 65001 >nul
title netryx_demo - 局域网设备查看
cd /d "%~dp0engine"
echo ============================================
echo  netryx_demo - 局域网设备与连接管理
echo.
echo  本机 IPv4 地址(192.168.3.x 那条是该机在路由下的地址):
ipconfig | findstr /c:"IPv4"
echo.
echo  手机(同一 WiFi)访问  : http://192.168.3.235:8765  (以实际 IP 为准)
echo  本机浏览器访问        : http://127.0.0.1:8765
echo.
echo  首次启动:Windows 防火墙可能询问,请勾选"专用网络"并允许
echo  默认账号 admin / admin ;登录后请到 Settings 修改密码
echo  关闭此窗口即停止服务
echo ============================================
echo.
python netryx.py --host 0.0.0.0 --port 8765
pause
