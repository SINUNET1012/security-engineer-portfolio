from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional, Tuple

import nbformat
from pypdf import PdfReader


PDF_PATH = Path(__file__).resolve().parents[2] / "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf"
INDEX_PATH = Path(__file__).resolve().parents[1] / "_index" / "items.json"
OUT_ROOT = Path(__file__).resolve().parents[1]


DOMAIN_DIRNAME = {
    "UNIX": "01_Unix 서버",
    "Windows 서버": "02_Windows 서버",
    "웹 서비스": "03_웹 서비스",
    "보안 장비": "04_보안 장비",
    "네트워크 장비": "05_네트워크 장비",
    "제어시스템": "06_제어시스템",
    "PC": "07_PC",
    "DBMS": "08_DBMS",
    "이동통신": "09_이동통신",
    "가상화 장비": "10_가상화 장비",
    "클라우드": "11_클라우드",
}

END_TOKENS = ["관리", "통제", "대응", "훈련", "탐지"]


def sanitize_filename(text: str, *, max_len: int = 120) -> str:
    text = text.strip()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r'[\\/:*?"<>|]', "_", text)
    text = text.replace("\n", " ").replace("\r", " ")
    text = re.sub(r"_+", "_", text).strip("_ ")
    if not text:
        return "untitled"
    if len(text) > max_len:
        text = text[:max_len].rstrip()
    return text


def split_category_title(tail: str) -> Tuple[str, str]:
    positions: List[int] = []
    for token in END_TOKENS:
        idx = tail.find(token)
        if idx != -1:
            positions.append(idx + len(token))
    if not positions:
        return "", tail.strip()
    end_idx = min(positions)
    return tail[:end_idx].strip(), tail[end_idx:].strip()


def extract_judgement(text: str) -> Tuple[Optional[str], Optional[str]]:
    m = re.search(
        r"판단 기준\\s*양호\\s*:\\s*(?P<good>.*?)\\s*취약\\s*:\\s*(?P<bad>.*?)(?:조치 방법|조치\\s*시\\s*영향|점검 및 조치 사례|점검\\s*및\\s*조치\\s*사례|참고|$)",
        text,
        flags=re.S,
    )
    if not m:
        return None, None
    good = re.sub(r"\s+", " ", m.group("good")).strip()
    bad = re.sub(r"\s+", " ", m.group("bad")).strip()
    return good or None, bad or None


def build_notebook(
    *,
    code: str,
    importance: str,
    domain: str,
    section_num: int,
    category: str,
    title: str,
    page_start: int,
    page_end: int,
    raw_text: str,
) -> nbformat.NotebookNode:
    good, bad = extract_judgement(raw_text)

    func_name = code.replace("-", "_")

    code_lines: List[str] = []
    code_lines.append("import sys")
    code_lines.append("from pathlib import Path")
    code_lines.append("")
    code_lines.append("# 실행 권장: Jupyter를 `2026 주정통 코드 정리` 폴더에서 실행")
    code_lines.append("# (현재 작업 디렉터리 기준으로 server.py를 찾을 수 있도록 sys.path를 보정)")
    code_lines.append("for p in [Path.cwd(), *Path.cwd().resolve().parents]:")
    code_lines.append("    if (p / 'server.py').exists():")
    code_lines.append("        sys.path.insert(0, str(p))")
    code_lines.append("        break")
    code_lines.append("")
    code_lines.append("from server import Server")
    code_lines.append("")
    code_lines.append(f"def {func_name}(server):")
    code_lines.append("    # 작성자 : 자동생성")
    code_lines.append("    # 작성일 : 2026-01-05")
    code_lines.append(f"    # 점검 항목 : {title} ({code})")
    code_lines.append(f"    # 중요도 : {importance}")
    code_lines.append(f"    # 점검 영역 : {domain} > {section_num}. {category}".rstrip())
    code_lines.append("    # 판단 기준")
    code_lines.append(f"    #   양호 : {good if good else '가이드 참고'}")
    code_lines.append(f"    #   취약 : {bad if bad else '가이드 참고'}")
    code_lines.append("")
    code_lines.append("    output = 2  # 기본값(점검 실패/수동 확인 필요)")
    code_lines.append("    try:")
    code_lines.append("        # TODO: 항목별 자동화 로직 구현")
    code_lines.append("        # - 가이드의 점검 및 조치 사례를 참고하여 명령/설정 파싱을 구현하세요.")
    code_lines.append("        # - 자동화가 어려운 항목은 증거 수집 후 output=2로 유지하고 수동 판단을 유도하세요.")
    code_lines.append("        output = 2")
    code_lines.append("    except Exception:")
    code_lines.append("        output = 2")
    code_lines.append("    return output")
    code_lines.append("")
    code_lines.append("if __name__ == \"__main__\":")
    code_lines.append("    # 실행 예시(필요시 수정)")
    code_lines.append("    myServer = Server(\"127.0.0.1\", \"\", \"root\", \"\")")
    code_lines.append(f"    result = {func_name}(myServer)")
    code_lines.append("    print(result)")

    nb = nbformat.v4.new_notebook()
    nb["cells"] = [
        nbformat.v4.new_markdown_cell(
            f"# {code} ({importance})\\n\\n"
            f"- 영역: {domain}\\n"
            f"- 분류: {section_num}. {category}\\n"
            f"- 항목: {title}\\n"
            f"- 페이지: {page_start}~{page_end}\\n"
        ),
        nbformat.v4.new_markdown_cell(
            "## 판단 기준(가이드 발췌)\\n\\n"
            f"- 양호: {good if good else '추출 실패(원문 확인 필요)'}\\n"
            f"- 취약: {bad if bad else '추출 실패(원문 확인 필요)'}\\n\\n"
            "## 원문(자동 추출)\\n\\n"
            "```\\n"
            + raw_text.strip()
            + "\\n```\\n"
        ),
        nbformat.v4.new_code_cell("\\n".join(code_lines)),
    ]
    nb["metadata"] = {
        "kernelspec": {"display_name": "Python 3 (ipykernel)", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "mimetype": "text/x-python", "file_extension": ".py"},
    }
    nb["nbformat"] = 4
    nb["nbformat_minor"] = 5
    return nb


def main() -> int:
    items = json.loads(INDEX_PATH.read_text(encoding="utf-8"))

    reader = PdfReader(str(PDF_PATH))
    page_texts = [page.extract_text() or "" for page in reader.pages]

    created = 0
    for it in items:
        domain = it["domain"]
        domain_dir = DOMAIN_DIRNAME.get(domain, "99_기타")

        section_num = int(it.get("section_num") or 0)
        category = str(it.get("category") or "").strip()
        title = str(it.get("title") or "").strip()

        section_dir_name = (
            f"{section_num:02d}_{sanitize_filename(category or '기타', max_len=60)}" if section_num else "00_기타"
        )
        out_dir = OUT_ROOT / domain_dir / section_dir_name
        out_dir.mkdir(parents=True, exist_ok=True)

        filename = f"{it['code']}_{sanitize_filename(title, max_len=80)}.ipynb"
        out_path = out_dir / filename

        raw_text = "\\n".join(page_texts[int(it["page_start"]) - 1 : int(it["page_end"]) + 0]).strip()

        nb = build_notebook(
            code=it["code"],
            importance=it["importance"],
            domain=domain,
            section_num=section_num,
            category=category,
            title=title,
            page_start=int(it["page_start"]),
            page_end=int(it["page_end"]),
            raw_text=raw_text,
        )

        nbformat.write(nb, str(out_path))
        created += 1

    print(f"created {created} notebooks under: {OUT_ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

