from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXCERPT_MARKERS = (
    "판단 기준(가이드 발췌)",
    "원문(자동 추출)",
)
META_MARKERS = (
    "- 영역:",
    "- 분류:",
    "- 항목:",
    "- 페이지:",
)

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _cell_text(cell: dict) -> str:
    src = cell.get("source") or ""
    if isinstance(src, list):
        return "".join(src)
    return str(src)


_CODE_RE = re.compile(r"^[A-Z]+-\d+$")


def _infer_code_from_path(nb_path: Path) -> str:
    # 파일명 규칙: <CODE>_<TITLE>.ipynb (예: U-01_xxx.ipynb, WEB-04_xxx.ipynb)
    return nb_path.stem.split("_", 1)[0].strip().upper()


def _implemented_in_checks(code: str) -> bool:
    module_name: str
    if code.startswith("U-"):
        module_name = "checks.unix"
    elif code.startswith("W-"):
        module_name = "checks.windows"
    elif code.startswith("WEB-"):
        module_name = "checks.web"
    elif code.startswith("S-"):
        module_name = "checks.security"
    elif code.startswith("N-"):
        module_name = "checks.network"
    elif code.startswith("D-"):
        module_name = "checks.dbms"
    else:
        return False

    try:
        mod = __import__(module_name, fromlist=["CHECKS"])
    except Exception:
        return False
    checks = getattr(mod, "CHECKS", None)
    return isinstance(checks, dict) and code in checks


def is_completed(nb_path: Path, nb: dict) -> bool:
    code = _infer_code_from_path(nb_path)
    if not _CODE_RE.fullmatch(code):
        return False
    return _implemented_in_checks(code)


def strip_excerpts(nb: dict) -> bool:
    new_cells = []
    removed = False
    for cell in nb.get("cells", []):
        if cell.get("cell_type") == "markdown":
            text = _cell_text(cell)
            if any(m in text for m in EXCERPT_MARKERS) or any(m in text for m in META_MARKERS):
                removed = True
                continue
        new_cells.append(cell)
    if removed:
        nb["cells"] = new_cells
    return removed


def main() -> int:
    updated = 0
    for nb_path in ROOT.rglob("*.ipynb"):
        nb = json.loads(nb_path.read_text(encoding="utf-8"))
        if not is_completed(nb_path, nb):
            continue
        if not strip_excerpts(nb):
            continue
        nb_path.write_text(json.dumps(nb, ensure_ascii=False, indent=1), encoding="utf-8")
        updated += 1
    print(f"removed excerpts from {updated} completed notebooks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
