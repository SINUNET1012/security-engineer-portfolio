#!/bin/bash

# ==========================================
# Snort 2.9.20 자동 설치 스크립트 (최종_v2)
# ==========================================

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}이 스크립트는 root 권한으로 실행해야 합니다.${NC}"
  exit 1
fi

echo -e "${GREEN}[Step 0] 사전 환경 점검...${NC}"
# 이미 정리했으므로 에러 무시하고 넘어감
sudo add-apt-repository --remove ppa:ondrej/php -y 2>/dev/null || true
sudo rm -f /etc/apt/sources.list.d/ondrej-ubuntu-php-*.list 2>/dev/null || true

echo -e "${GREEN}[Step 1] 작업 디렉터리 및 패키지 확인...${NC}"
mkdir -p /root/Snort
cd /root/Snort

# 패키지 설치 (이미 설치되어 있으면 빠르게 넘어감)
apt-get update
apt-get install -y build-essential libpcap-dev libpcre3-dev zlib1g-dev \
libssl-dev uuid-dev flex bison libdumbnet-dev libtirpc-dev libtirpc3 \
openssl libnghttp2-dev

echo -e "${GREEN}[Step 2] 소스 파일 다운로드 (링크 수정됨)...${NC}"

# wget 옵션: -c (이어받기), -O (파일이름 지정)
wget -c https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz --no-check-certificate
wget -c http://www.tcpdump.org/release/libpcap-1.8.1.tar.gz

# [수정] LuaJIT 공식 사이트가 죽어서 GitHub 아카이브로 변경
# 다운로드 후 파일명을 LuaJIT-2.0.5.tar.gz로 저장
wget -O LuaJIT-2.0.5.tar.gz https://github.com/LuaJIT/LuaJIT/archive/refs/tags/v2.0.5.tar.gz

wget -c https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz --no-check-certificate

echo -e "${GREEN}[Step 3] Libpcap 1.8.1 설치...${NC}"
tar -xvf libpcap-1.8.1.tar.gz
cd libpcap-1.8.1
./configure
make && make install
cd ..

echo -e "${GREEN}[Step 4] DAQ 2.0.7 설치...${NC}"
tar -xvf daq-2.0.7.tar.gz
cd daq-2.0.7
./configure
make && make install
cd ..

echo -e "${GREEN}[Step 5] LuaJIT 2.0.5 설치...${NC}"
tar -xvf LuaJIT-2.0.5.tar.gz
# GitHub 아카이브는 압축 풀면 폴더명이 다를 수 있어서 확인 후 이동
if [ -d "LuaJIT-2.0.5" ]; then
  cd LuaJIT-2.0.5
else
  # 보통 v2.0.5로 풀리거나 LuaJIT-2.0.5로 풀림. 안전장치
  cd LuaJIT*2.0.5*
fi

make && make install
cd ..

ldconfig

echo -e "${GREEN}[Step 6] Snort 2.9.20 컴파일 및 설치...${NC}"
tar -xvf snort-2.9.20.tar.gz
cd snort-2.9.20
./configure --enable-sourcefire CPPFLAGS="-I/usr/include/tirpc" LDFLAGS="-ltirpc" LIBS="-ltirpc"
make
make install
cd ..

echo -e "${GREEN}[Step 7] Snort 사용자 및 그룹 설정...${NC}"
if ! getent group snort > /dev/null; then
  groupadd snort
fi
if ! id -u snort > /dev/null 2>&1; then
  useradd snort -r -s /sbin/nologin -g snort
fi

echo -e "${GREEN}[Step 8] 디렉터리 및 설정 파일 복사...${NC}"
mkdir -p /etc/snort/rules
mkdir -p /etc/snort/preproc_rules
mkdir -p /usr/local/lib/snort_dynamicrules
mkdir -p /var/log/snort
touch /etc/snort/rules/white_list.rules
touch /etc/snort/rules/black_list.rules

cd /root/Snort/snort-2.9.20/etc
cp *.conf* /etc/snort
cp *.map /etc/snort
cp *.dtd /etc/snort

SRC_PREPROC="/root/Snort/snort-2.9.20/src/dynamic-preprocessors/build/usr/local/lib/snort_dynamic_preprocessor/"
DEST_PREPROC="/usr/local/lib/snort_dynamicrules/"
if [ -d "$SRC_PREPROC" ]; then
    cp $SRC_PREPROC/* $DEST_PREPROC
fi

echo -e "${GREEN}[Step 9] 권한 설정...${NC}"
chmod -R 5775 /var/log/snort
chmod -R 5775 /etc/snort
chmod -R 5775 /usr/local/lib/snort_dynamicrules
chown -R snort:snort /var/log/snort
chown -R snort:snort /etc/snort
chown -R snort:snort /usr/local/lib/snort_dynamicrules

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}       Snort 설치가 완료되었습니다.      ${NC}"
echo -e "${GREEN}======================================${NC}"
snort -V