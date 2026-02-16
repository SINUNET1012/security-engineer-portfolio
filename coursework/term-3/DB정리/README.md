# 3차 프로젝트 공유 DB(CMDB) CSV 템플릿

이 폴더의 CSV는 서버팀/네트워크팀/퍼플팀이 함께 쓰는 “한 개 DBMS(CMDB)”에 적재할 테이블 양식(헤더)입니다.

## 공통 기준(매뉴얼 반영)
- 네이밍: `<REGION>-<ROLE>-<OS>-<NN>` (예: `ASIA-DB-ROCKY-01`)
- 최소 태그: `region`, `role`, `os`, `env`, `owner_team`
- 로그 인벤토리 기본값: Linux(auth/sudo), Windows(Security), DBMS(접속/감사), 장비(Syslog)

## 파일
- `inventory.csv`: (핵심) 서버/장비 목록 + 접속정보 + 지역/수집 엔드포인트
- `logsources.csv`: (핵심) 호스트별 수집 로그(경로/채널)
- `whitelist.csv`: (핵심) 자동 차단 제외 목록

## 선택(고급/정규화)
- `advanced/regions.csv`: 지역 엔드포인트 분리(정규화)
- `advanced/services.csv`: 서비스 사전(정규화)
- `advanced/servicemap.csv`: 서비스-호스트 매핑(정규화)
- `advanced/interfaces.csv`: 멀티 인터페이스/멀티 IP 분리(정규화)
