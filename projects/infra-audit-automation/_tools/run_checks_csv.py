from __future__ import annotations

import argparse
import contextlib
import csv
import datetime as dt
import getpass
import io
import json
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# `2026 주정통 코드 정리` 폴더 내에서 실행하는 것을 권장합니다.
ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = ROOT / "_index" / "items.json"

CSV_FIELDS = [
    "host",
    "host_memo",
    "code",
    "result",
    "result_label",
    "updated_at",
    "duration_ms",
    "domain",
    "section",
    "category",
    "title",
    "importance",
    "detail",
]

RESULT_LABEL = {0: "양호", 1: "취약", 2: "수동확인/점검실패"}


def _load_index() -> Dict[str, dict]:
    items = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    return {str(it["code"]): it for it in items}


def _dedupe_keep_order(values: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for v in values:
        if v in seen:
            continue
        out.append(v)
        seen.add(v)
    return out


def _parse_codes(codes: Optional[str], codes_file: Optional[str]) -> List[str]:
    items: List[str] = []
    if codes:
        for part in codes.split(","):
            part = part.strip()
            if part:
                items.append(part)

    if codes_file:
        path = Path(codes_file)
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            items.append(line)

    items = [c.upper() for c in items]
    return _dedupe_keep_order(items)


def _host_id(host: str, port: int) -> str:
    host = host.strip()
    return host if port == 22 else f"{host}:{port}"


def _read_existing_csv(path: Path) -> Dict[Tuple[str, str], Dict[str, str]]:
    if not path.exists():
        return {}
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows: Dict[Tuple[str, str], Dict[str, str]] = {}
        for row in reader:
            host = (row.get("host") or "").strip()
            code = (row.get("code") or "").strip().upper()
            if not host or not code:
                continue
            rows[(host, code)] = {k: (v if v is not None else "") for k, v in row.items()}
        return rows


def _write_csv(path: Path, rows: Mapping[Tuple[str, str], Mapping[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for (host, code) in sorted(rows.keys(), key=lambda x: (x[0], x[1])):
            writer.writerow(dict(rows[(host, code)]))


def _escape_one_line(text: str) -> str:
    # MariaDB LOAD DATA에서 줄 단위 처리가 쉬우려면 실제 줄바꿈은 이스케이프해서 1행=1결과로 유지하는 것이 안전합니다.
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\\n")


def _run_one(code: str, server, *, verbose: bool) -> int:
    if code.startswith("U-"):
        from checks.unix import run as run_check

        return run_check(code, server, verbose=verbose)
    if code.startswith("W-"):
        from checks.windows import run as run_check

        return run_check(code, server, verbose=verbose)
    if code.startswith("WEB-"):
        from checks.web import run as run_check

        return run_check(code, server, verbose=verbose)
    if code.startswith("S-"):
        from checks.security import run as run_check

        return run_check(code, server, verbose=verbose)
    if code.startswith("N-"):
        from checks.network import run as run_check

        return run_check(code, server, verbose=verbose)
    if verbose:
        print(f"[{code}] 미구현(수동 확인 필요)")
    return 2


def run_checks_to_csv(
    *,
    host: str,
    user: str,
    password: Optional[str] = None,
    port: int = 22,
    key: Optional[str] = None,
    timeout: int = 10,
    codes: Sequence[str],
    host_memo: str = "",
    out: Union[str, Path] = ROOT / "_results" / "results.csv",
    show_detail: bool = False,
) -> Path:
    codes_norm = _dedupe_keep_order([str(c).strip().upper() for c in codes if str(c).strip()])
    if not codes_norm:
        raise ValueError("codes is empty")

    if password is None and not key:
        raise ValueError("password 또는 key 중 하나는 필요합니다.")

    index = _load_index()
    out_csv = Path(out)
    existing = _read_existing_csv(out_csv)

    target = _host_id(host, int(port))
    host_memo = str(host_memo or "").strip()
    updated_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 프로젝트 루트에서 실행하더라도 import가 되도록 sys.path 보정
    sys.path.insert(0, str(ROOT))
    from server import Server

    with Server(
        host,
        "",
        user,
        password or "",
        port=int(port),
        timeout=int(timeout),
        key_filename=key,
    ) as server:
        for code in codes_norm:
            meta = index.get(code, {})

            buf = io.StringIO()
            started = time.monotonic()
            with contextlib.redirect_stdout(buf):
                result = _run_one(code, server, verbose=True)
            duration_ms = int((time.monotonic() - started) * 1000)

            detail = _escape_one_line(buf.getvalue().strip())
            result_label = RESULT_LABEL.get(int(result), "UNKNOWN")

            row: Dict[str, str] = {
                "host": target,
                "host_memo": host_memo,
                "code": code,
                "result": str(int(result)),
                "result_label": result_label,
                "updated_at": updated_at,
                "duration_ms": str(duration_ms),
                "domain": str(meta.get("domain") or ""),
                "section": str(meta.get("section") or ""),
                "category": str(meta.get("category") or ""),
                "title": str(meta.get("title") or ""),
                "importance": str(meta.get("importance") or ""),
                "detail": detail,
            }

            existing[(target, code)] = row
            print(f"{target} {code} -> {result_label}({result})")
            if show_detail and detail:
                print(detail)

    _write_csv(out_csv, existing)
    print(f"saved: {out_csv}")
    return out_csv


def main() -> int:
    parser = argparse.ArgumentParser(description="주정통 항목 점검 결과를 CSV로 저장(upsert: host+code 기준)")
    parser.add_argument("--host", required=True, help="대상 서버 IP/호스트명")
    parser.add_argument("--port", type=int, default=22, help="SSH 포트(기본 22)")
    parser.add_argument("--user", required=True, help="SSH 계정명")
    parser.add_argument("--host-memo", default="", help="서버 메모(예: 웹/DNS/DB/보안장비 등)")
    parser.add_argument("--password", default=None, help="SSH 비밀번호(미지정 시 프롬프트 입력)")
    parser.add_argument("--key", default=None, help="SSH 개인키 경로(비밀번호 대신 사용 가능)")
    parser.add_argument("--timeout", type=int, default=10, help="SSH 타임아웃(초)")
    parser.add_argument("--codes", default=None, help="콤마로 구분한 코드 목록(예: U-01,U-02)")
    parser.add_argument("--codes-file", default=None, help="코드 목록 파일(한 줄에 1개, # 주석 가능)")
    parser.add_argument("--out", default=str(ROOT / "_results" / "results.csv"), help="결과 CSV 경로")
    parser.add_argument("--show-detail", action="store_true", help="콘솔에 detail 출력")
    args = parser.parse_args()

    codes = _parse_codes(args.codes, args.codes_file)
    if not codes:
        print("선택한 코드가 없습니다. --codes 또는 --codes-file을 지정하세요.", file=sys.stderr)
        return 2

    password = args.password
    if password is None and not args.key:
        password = getpass.getpass("SSH Password: ")
    run_checks_to_csv(
        host=args.host,
        port=int(args.port),
        user=args.user,
        password=password,
        key=args.key,
        timeout=int(args.timeout),
        codes=codes,
        host_memo=str(args.host_memo or ""),
        out=args.out,
        show_detail=bool(args.show_detail),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
