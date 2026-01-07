from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = ROOT / "_index" / "items.json"
NET_ROOT = ROOT / "05_네트워크 장비"


def build_code_cell(it: dict) -> str:
    code = str(it["code"])
    func_name = code.replace("-", "_")
    importance = str(it.get("importance") or "")
    domain = str(it.get("domain") or "")
    section_num = int(it.get("section_num") or 0)
    category = str(it.get("category") or "").strip()
    title = str(it.get("title") or "").strip()

    area = f"{domain} > {section_num}. {category}".rstrip()

    lines: list[str] = []
    lines.append("import sys")
    lines.append("from pathlib import Path")
    lines.append("")
    lines.append("# 실행 권장: Jupyter를 `2026 주정통 코드 정리` 폴더에서 실행")
    lines.append("# (현재 작업 디렉터리 기준으로 server.py / checks 패키지를 찾을 수 있도록 sys.path를 보정)")
    lines.append("for p in [Path.cwd(), *Path.cwd().resolve().parents]:")
    lines.append("    if (p / 'server.py').exists():")
    lines.append("        sys.path.insert(0, str(p))")
    lines.append("        break")
    lines.append("")
    lines.append("from server import Server")
    lines.append("from checks.network import run as run_check")
    lines.append("")
    lines.append(f"def {func_name}(server, verbose: bool = True):")
    lines.append("    # 작성자 : 자동생성")
    lines.append("    # 작성일 : 2026-01-05")
    lines.append(f"    # 점검 항목 : {title} ({code})")
    lines.append(f"    # 중요도 : {importance}")
    lines.append(f"    # 점검 영역 : {area}")
    lines.append("")
    lines.append(f"    return run_check('{code}', server, verbose=verbose)")
    lines.append("")
    lines.append('if __name__ == "__main__":')
    lines.append("    # 실행 예시(필요시 수정)")
    lines.append('    myServer = Server("127.0.0.1", "", "root", "")')
    lines.append(f"    result = {func_name}(myServer)")
    lines.append("    print(result)")
    return "\n".join(lines)


def find_notebook_path(code: str) -> Path:
    matches = list(NET_ROOT.rglob(f"{code}_*.ipynb"))
    if len(matches) != 1:
        raise FileNotFoundError(f"{code}: expected 1 notebook, got {len(matches)}")
    return matches[0]


def main() -> int:
    items = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    n_items = [it for it in items if str(it.get("code", "")).startswith("N-")]

    updated = 0
    for it in n_items:
        code = str(it["code"])
        nb_path = find_notebook_path(code)
        nb = json.loads(nb_path.read_text(encoding="utf-8"))

        code_cells = [i for i, cell in enumerate(nb.get("cells", [])) if cell.get("cell_type") == "code"]
        if not code_cells:
            raise RuntimeError(f"{nb_path}: no code cell found")
        nb["cells"][code_cells[-1]]["source"] = [build_code_cell(it)]
        nb_path.write_text(json.dumps(nb, ensure_ascii=False, indent=1), encoding="utf-8")
        updated += 1

    print(f"updated {updated} Network(N) notebooks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
