# 주요정보통신시설 점검 자동화(전체 항목)

## 폴더 구조
- `_index/`: PDF에서 추출한 항목 인덱스(`items.json`, `items.csv`)
- `_tools/`: 생성 스크립트(`generate_ipynb_all.py`)
- `01_Unix 서버/` ~ `11_클라우드/`: 세션(영역)별 폴더
  - 각 세션 폴더 아래에 `NN_<분류>` 폴더가 있고, 그 안에 **항목 1개 = ipynb 1개**가 생성됩니다.

## 공통 코드
- `server.py`: SSH 접속 유틸(2025 스타일 호환: `ssh()`가 stdout 객체 반환)
- `checks/`: 자동판정(0/1/2) 공통 로직(현재: `checks/unix.py`, `checks/windows.py`, `checks/web.py`, `checks/security.py`, `checks/network.py`)

## 노트북 실행 팁
- `import server`가 잘 되도록, Jupyter를 **프로젝트 루트(현재 폴더)** 에서 실행하는 것을 권장합니다.

## 재생성(필요 시)
```bash
python3 _tools/generate_ipynb_all.py
```

## UNIX(U-xx) 로직 재적용(필요 시)
```bash
python3 _tools/apply_unix_logic.py
```

## WEB(WEB-xx) 로직 재적용(필요 시)
```bash
python3 _tools/apply_web_logic.py
```

## 보안 장비(S-xx) 로직 재적용(필요 시)
```bash
python3 _tools/apply_security_logic.py
```

## 네트워크 장비(N-xx) 로직 재적용(필요 시)
```bash
python3 _tools/apply_network_logic.py
```

## 선택 항목 일괄 점검 + CSV 저장(덮어쓰기)
- 결과는 `host + code` 기준으로 **덮어쓰기(upsert)** 되며, 최신 실행 시각은 `updated_at`에 기록됩니다.
- 서버 용도/종류 메모가 필요하면 `--host-memo`로 함께 저장할 수 있습니다(컬럼: `host_memo`).

```bash
cd projects/infra-audit-automation

# 예) U-01, U-02만 선택 실행
python3 _tools/run_checks_csv.py --host 192.168.0.10 --user root --host-memo "웹서버" --codes U-01,U-02

# 예) 코드 목록 파일로 실행(한 줄에 1개)
python3 _tools/run_checks_csv.py --host 192.168.0.10 --user root --codes-file my_codes.txt

# 기본 출력: projects/infra-audit-automation/_results/results.csv
```

## 세션별 마스터(노트북)
- `01_Unix 서버/MASTER_01_Unix_점검.ipynb`
- `02_Windows 서버/MASTER_02_Windows_점검.ipynb` (Windows OpenSSH + PowerShell 기준)
- `03_웹 서비스/MASTER_03_Web_점검.ipynb`
- `04_보안 장비/MASTER_04_Security_점검.ipynb`
- `05_네트워크 장비/MASTER_05_Network_점검.ipynb`

## 업데이트 규칙
- 점검 항목별 Notebook/로직 업데이트 시, `01_Unix 서버`의 구조/패턴을 기준으로 동일한 규칙을 적용하는 것을 권장합니다.
