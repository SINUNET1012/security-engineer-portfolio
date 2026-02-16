@echo "off"
@chcp 65001
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /t REG_DWORD /v ProxyEnable /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /t REG_SZ /v ProxyServer /d 172.16.23.70:8080 /f
.\beeboximage.png

netsh -c int ip set dns name="이더넷" static 172.16.23.250
ipconfig /flushdns
start http://ww1.ubi.ck