# 신입 보안 엔지니어 포트폴리오 (Security Engineer Portfolio)

인프라 보안 점검 자동화, 보안 관제·대응 시나리오 정리, 모의해킹/보안정책 산출물, 문서 자동화 도구를 한 레포에서 탐색할 수 있도록 구성한 포트폴리오입니다.

## Highlights
- `projects/infra-audit-automation/` : SSH 기반 점검 자동화(Unix/Windows/Web/보안장비/네트워크 장비) + 결과 CSV 업서트
- `projects/portfolio-slide-generator/` : PDF 일부 페이지를 자동 렌더링해 PPTX 포트폴리오를 생성하는 스크립트(PyMuPDF/Pillow/python-pptx)
- `projects/report-template-generator/` : 보안정책 구현 결과보고서(DOCX) 템플릿 생성기(python-docx)

## Quick Start
```bash
# (선택) 프로젝트별 의존성 설치
pip install -r projects/infra-audit-automation/requirements.txt
pip install -r projects/portfolio-slide-generator/requirements.txt
pip install -r projects/report-template-generator/requirements.txt

# 포트폴리오 PPTX 생성
python3 projects/portfolio-slide-generator/generate_portfolio_ppt.py --out "profile/Portfolio.pptx"

# 결과보고서(DOCX) 템플릿 생성
python3 projects/report-template-generator/generate_result_report.py --out "reports/security-policy-implementation/보안정책_구현_결과보고서_템플릿.docx"
```

## Reports
- `reports/pentest/` : 모의해킹 보고서(문서)
- `reports/security-monitoring/` : 네트워크 보안관제 보고서(문서)
- `reports/security-policy/` / `reports/security-policy-implementation/` : 보안정책 문서 및 구현 결과보고서(문서)

## Docs
- `docs/project-proposals/` : 프로젝트 기획안(버전별)
- `docs/specs/` : 함수정의서 등 스펙 문서
- `docs/testing/` / `docs/dashboards/` : 테스트·검증 계획, 결과 대시보드
- `docs/manuals/` : 구축/실습 매뉴얼
