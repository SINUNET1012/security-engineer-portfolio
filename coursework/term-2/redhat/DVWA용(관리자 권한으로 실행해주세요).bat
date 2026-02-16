@echo "off"
@chcp 65001

netsh -c int ip set dns name="이더넷" static 172.16.254.6
ipconfig /flushdns