#!/bin/bash

# ==========================================
# Snort 2.9.20 자동 설치 스크립트 (Rocky 10 대응 수정판)
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

echo -e "${GREEN}[Step 0] 사전 환경 점검 및 저장소 설정...${NC}"

# Rocky Linux 필수 저장소 확인
if ! rpm -q epel-release > /dev/null; then
    dnf install -y epel-release
fi

# CRB(Rocky 9/10) 활성화 시도
dnf config-manager --set-enabled crb 2>/dev/null || true

echo -e "${GREEN}[Step 1] 작업 디렉터리 및 패키지 설치...${NC}"
mkdir -p /root/Snort
cd /root/Snort

# 필수 패키지 설치
# [수정됨] pcre-devel을 목록에서 제거 (Rocky 10에 없음)
dnf install -y wget tar xz make gcc gcc-c++ flex bison \
libpcap-devel zlib-devel openssl-devel \
libuuid-devel libdnet-devel libtirpc-devel libnghttp2-devel

# [RHEL 특화] libdnet 호환성 패치
if [ ! -f /usr/include/dumbnet.h ] && [ -f /usr/include/dnet.h ]; then
    echo -e "${YELLOW}libdnet 호환성을 위해 심볼릭 링크 생성 중...${NC}"
    ln -s /usr/include/dnet.h /usr/include/dumbnet.h 2>/dev/null || true
    ln -s /usr/lib64/libdnet.so /usr/lib64/libdumbnet.so 2>/dev/null || true
fi

echo -e "${GREEN}[Step 2] 소스 파일 다운로드...${NC}"

# Snort 및 관련 파일 다운로드
wget -c https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz --no-check-certificate
wget -c http://www.tcpdump.org/release/libpcap-1.8.1.tar.gz
wget -c -O LuaJIT-2.0.5.tar.gz https://github.com/LuaJIT/LuaJIT/archive/refs/tags/v2.0.5.tar.gz
wget -c https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz --no-check-certificate

# [추가됨] PCRE 8.45 다운로드 (Rocky 10 호환성 해결용)
echo -e "${GREEN}[Step 2-1] PCRE 8.45 소스 다운로드 (Rocky 10 대응)...${NC}"
wget -c https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz

echo -e "${GREEN}[Step 3] Libpcap 1.8.1 설치...${NC}"
tar -xvf libpcap-1.8.1.tar.gz
cd libpcap-1.8.1
./configure
make && make install
cd ..

# [추가됨] PCRE 8.45 수동 설치
echo -e "${GREEN}[Step 3-1] PCRE 8.45 컴파일 및 설치...${NC}"
tar -xvf pcre-8.45.tar.gz
cd pcre-8.45
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
if [ -d "LuaJIT-2.0.5" ]; then
  cd LuaJIT-2.0.5
else
  cd LuaJIT*2.0.5*
fi
make && make install
cd ..

# 라이브러리 경로 갱신
if ! grep -q "/usr/local/lib" /etc/ld.so.conf; then
    echo "/usr/local/lib" >> /etc/ld.so.conf.d/snort.conf
fi
ldconfig

echo -e "${GREEN}[Step 6] Snort 2.9.20 컴파일 및 설치...${NC}"
tar -xvf snort-2.9.20.tar.gz
cd snort-2.9.20

# configure 실행
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

SRC_PREPROC_BASE="/root/Snort/snort-2.9.20/src/dynamic-preprocessors/build/usr/local/lib/snort_dynamic_preprocessor"
if [ -d "$SRC_PREPROC_BASE" ]; then
    cp $SRC_PREPROC_BASE/* /usr/local/lib/snort_dynamicrules/
else
    echo -e "${YELLOW}Warning: Dynamic Preprocessor 경로를 찾지 못했습니다.${NC}"
fi

echo -e "${GREEN}[Step 9] 권한 설정...${NC}"
chmod -R 5775 /var/log/snort
chmod -R 5775 /etc/snort
chmod -R 5775 /usr/local/lib/snort_dynamicrules
chown -R snort:snort /var/log/snort
chown -R snort:snort /etc/snort
chown -R snort:snort /usr/local/lib/snort_dynamicrules

ln -s /usr/local/bin/snort /usr/sbin/snort 2>/dev/null || true

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}      Snort 설치가 완료되었습니다.      ${NC}"
echo -e "${GREEN}======================================${NC}"
snort -V