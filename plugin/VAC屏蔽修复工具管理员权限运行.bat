@echo off
color a

goto steam

:steam
echo 正在检测Steam是否开启......
tasklist | find /I "Steam.exe"
if errorlevel 1 goto steamchina
if not errorlevel 1 goto start

:steamchina
echo 正在检测国服启动器是否开启......
tasklist | find /I "steamchina.exe"
if errorlevel 1 goto stop
if not errorlevel 1 goto start

:stop
echo Steam和国服启动器均未开启
goto start

:killsteam
echo Steam已开启
echo 正在强制关闭
taskkill /F /IM Steam.exe
echo 已强制关闭
goto start

:killsteamchina
echo Steam已开启
echo 正在强制关闭
taskkill /F /IM steamchina.exe
echo 已强制关闭
goto start

:start
echo 开始解决VAC屏蔽

echo 开启 Network Connections
sc config Netman start= AUTO
sc start Netman

echo 开启 Remote Access Connection Manager
sc config RasMan start= AUTO
sc start RasMan

echo 开启 Telephony
sc config TapiSrv start= AUTO
sc start TapiSrv

echo 开启 Windows Firewall
sc config MpsSvc start= AUTO
sc start MpsSvc
netsh advfirewall set allprofiles state on

echo 恢复 Data Execution Prevention 启动设置为默认值
bcdedit /deletevalue nointegritychecks
bcdedit /deletevalue loadoptions
bcdedit /debug off
bcdedit /deletevalue nx

echo 正在获取你的Steam或国服启动器目录
for /f "tokens=1,2,* " %%i in ('REG QUERY "HKEY_CURRENT_USER\SOFTWARE\Valve\Steam" ^| find /i "SteamPath"') do set "SteamPath=%%k" 
if "%SteamPath%" NEQ "0x1" (goto Auto) else (goto Manual)

:Auto
echo Steam或国服启动器目录为%SteamPath% 

echo 开始安装Steam Services
cd /d "%SteamPath%\bin"
steamservice  /install
ping -n 3 127.0.0.1>nul
echo 开始修复Steam Services
steamservice  /repair
ping -n 3 127.0.0.1>nul
echo .
echo 修复Steam Services完毕
echo 出现"Steam client service installation complete"且无任何"Fail"字样
echo (如"Add firewall exception failed for steamservice.exe"出现)才可以结束，
echo 否则请检查您的防火墙设置(关闭“不允许例外”选项)

echo 启动Steam Services服务
sc config "Steam Client Service" start= AUTO
sc start "Steam Client Service"

title 完毕!
echo                              完毕！按任意键结束窗口！
echo                              PS：一次只能获取Steam或国服启动器的目录
echo                              请提前运行一次想解决问题的启动器
echo                              快捷方式未对国服启动器进行适配
echo                              请自行将Steam.exe修改为steamchina.exe
exit
