# Portfolio Slide Generator

`generate_portfolio_ppt.py`는 PDF의 특정 페이지를 이미지로 렌더링한 뒤, 이를 조합해 PPTX 포트폴리오를 생성합니다.

## Requirements
- Python 3
- `pymupdf`, `Pillow`, `python-pptx`

## Usage
```bash
python3 projects/portfolio-slide-generator/generate_portfolio_ppt.py \
  --project-pdf "docs/project-proposals/2차 프로젝트 기획안 v0.9.pdf" \
  --server-policy-pdf "reports/security-policy/서버 보안 정책 문서(미완성).pdf" \
  --out "profile/Portfolio.pptx"
```

이력서 PDF를 함께 넣으면, Slide 5에 자동으로 삽입합니다.
```bash
python3 projects/portfolio-slide-generator/generate_portfolio_ppt.py \
  --resume-pdf "_private/resume/이력서_정보보안_박신우.pdf"
```

