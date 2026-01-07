from __future__ import annotations

import re
import shlex
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from server import Server


def run(code: str, server: Server, *, verbose: bool = True) -> int:
    func = CHECKS.get(code)
    if func is None:
        if verbose:
            print(f"[{code}] 미구현(수동 확인 필요)")
        return 2
    try:
        return func(server, verbose=verbose)
    except Exception as exc:
        if verbose:
            print(f"[{code}] 점검 실패: {exc}")
        return 2


def _q(value: str) -> str:
    return shlex.quote(value)


def _cmd(server: Server, cmd: str) -> str:
    return server.ssh_str(cmd)


def _command_exists(server: Server, name: str) -> bool:
    out = _cmd(server, f"command -v {_q(name)} >/dev/null 2>&1 && echo 1 || echo 0")
    return out.strip() == "1"


def _exists(server: Server, path: str) -> bool:
    out = _cmd(server, f"test -e {_q(path)} >/dev/null 2>&1 && echo 1 || echo 0")
    return out.strip() == "1"


def _is_windows(server: Server) -> bool:
    try:
        out = _cmd(
            server,
            "powershell.exe -NoProfile -NonInteractive -Command \"$PSVersionTable.PSVersion.Major\"",
        ).strip()
        return out.isdigit()
    except Exception:
        return False


def _read(server: Server, path: str) -> str:
    return _cmd(server, f"cat {_q(path)} 2>/dev/null || true")


def _dir_exists(server: Server, path: str) -> bool:
    out = _cmd(server, f"test -d {_q(path)} >/dev/null 2>&1 && echo 1 || echo 0")
    return out.strip() == "1"


def _existing_dirs(server: Server, paths: Sequence[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        if _dir_exists(server, p):
            out.append(p)
    return out


def _grep(server: Server, regex: str, paths: Sequence[str]) -> str:
    if not paths:
        return ""
    if not _command_exists(server, "grep"):
        return ""
    path_part = " ".join(_q(p) for p in paths)
    return _cmd(server, f"grep -RInE -- {_q(regex)} {path_part} 2>/dev/null | head -n 200 || true")


def _read_first_existing(server: Server, paths: Sequence[str]) -> Tuple[Optional[str], str]:
    for p in paths:
        if _exists(server, p):
            return p, _read(server, p)
    return None, ""


def _stat_mode(server: Server, path: str) -> Optional[int]:
    if not _exists(server, path):
        return None
    if _command_exists(server, "stat"):
        out = _cmd(
            server,
            f"stat -c '%a' {_q(path)} 2>/dev/null || stat -f '%Lp' {_q(path)} 2>/dev/null || true",
        ).strip()
        if out and out.isdigit():
            try:
                return int(out, 8)
            except Exception:
                return None
    out = _cmd(server, f"ls -ld {_q(path)} 2>/dev/null || true").strip()
    if not out:
        return None
    perm = out.split()[0]
    return _permstr_to_mode(perm)


def _permstr_to_mode(perm: str) -> Optional[int]:
    if not perm or len(perm) < 10:
        return None
    mapping = {"r": 4, "w": 2, "x": 1, "-": 0, "s": 1, "S": 0, "t": 1, "T": 0}
    triples = [perm[1:4], perm[4:7], perm[7:10]]
    mode = 0
    for tri in triples:
        val = mapping.get(tri[0], 0) * 4 + mapping.get(tri[1], 0) * 2 + mapping.get(tri[2], 0)
        mode = (mode << 3) + val
    if perm[3] in ("s", "S"):
        mode |= 0o4000
    if perm[6] in ("s", "S"):
        mode |= 0o2000
    if perm[9] in ("t", "T"):
        mode |= 0o1000
    return mode


def _ps_list(server: Server) -> List[str]:
    out = _cmd(server, "ps -eo user,comm,args 2>/dev/null || ps -ef 2>/dev/null || true")
    return out.splitlines()


def _curl_head(server: Server, url: str) -> str:
    if not _command_exists(server, "curl"):
        return ""
    return _cmd(server, f"curl -I -m 5 -s -o - {_q(url)} 2>/dev/null || true")


def _first_http_status(head_text: str) -> Optional[int]:
    for line in (head_text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.upper().startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
            return None
    return None


def _header_value(head_text: str, name: str) -> Optional[str]:
    prefix = name.lower() + ":"
    for line in (head_text or "").splitlines():
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return None


def _any_result(results: Iterable[int]) -> int:
    # 여러 웹서버가 공존할 수 있어 결과를 합칩니다.
    # - 하나라도 취약(1)이면 1
    # - 취약이 없고 하나라도 양호(0)이면 0
    # - 그 외는 2
    has_ok = False
    for r in results:
        if r == 1:
            return 1
        if r == 0:
            has_ok = True
    return 0 if has_ok else 2


def _nginx_dirs(server: Server) -> List[str]:
    return _existing_dirs(server, ["/etc/nginx", "/usr/local/nginx/conf", "/usr/local/etc/nginx"])


def _apache_dirs(server: Server) -> List[str]:
    return _existing_dirs(server, ["/etc/apache2", "/etc/httpd", "/usr/local/apache2/conf"])


def _tomcat_config_candidates() -> List[str]:
    return [
        "/etc/tomcat/server.xml",
        "/etc/tomcat9/server.xml",
        "/etc/tomcat8/server.xml",
        "/usr/share/tomcat/conf/server.xml",
        "/usr/share/tomcat9/conf/server.xml",
        "/usr/local/tomcat/conf/server.xml",
        "/opt/tomcat/conf/server.xml",
    ]


def _tomcat_webxml_candidates() -> List[str]:
    return [
        "/etc/tomcat/web.xml",
        "/etc/tomcat9/web.xml",
        "/etc/tomcat8/web.xml",
        "/usr/share/tomcat/conf/web.xml",
        "/usr/share/tomcat9/conf/web.xml",
        "/usr/local/tomcat/conf/web.xml",
        "/opt/tomcat/conf/web.xml",
    ]


def WEB_01(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-01] 수동 확인 필요: Default 관리자 계정명 변경 여부(제품/솔루션별 상이)")
    return 2


def WEB_02(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-02] 수동 확인 필요: 취약한 비밀번호 사용 제한 정책(계정/인증 체계별 상이)")
    return 2


def WEB_03(server: Server, *, verbose: bool = True) -> int:
    """
    WEB-03 비밀번호 파일 권한 관리
    - 양호: 비밀번호 파일 권한이 600 이하
    - 취약: 600 초과
    """

    if _is_windows(server):
        if verbose:
            print("[WEB-03] Windows(IIS) 환경은 수동 확인 필요(SAM 등)")
        return 2

    candidates = [
        # Tomcat
        "/etc/tomcat/tomcat-users.xml",
        "/etc/tomcat9/tomcat-users.xml",
        "/etc/tomcat8/tomcat-users.xml",
        "/usr/share/tomcat/conf/tomcat-users.xml",
        "/usr/share/tomcat9/conf/tomcat-users.xml",
        "/usr/local/tomcat/conf/tomcat-users.xml",
        "/opt/tomcat/conf/tomcat-users.xml",
        "/var/lib/tomcat9/conf/tomcat-users.xml",
        # JEUS(대표 경로 패턴)
        "/opt/jeus/domains/jeus_domain/config/security/SYSTEM_DOMAIN/accounts.xml",
        "/opt/jeus/domains/jeus_domain/config/security/SYSTEM_DOMAIN/policies.xml",
    ]

    found: List[Tuple[str, Optional[int]]] = []
    for path in candidates:
        if _exists(server, path):
            found.append((path, _stat_mode(server, path)))

    if not found and _command_exists(server, "find"):
        search_roots = ["/etc", "/usr/share", "/usr/local", "/opt", "/home"]
        root_part = " ".join(_q(p) for p in search_roots)
        out = _cmd(
            server,
            (
                f"find {root_part} -maxdepth 7 "
                f"\\( -name 'tomcat-users.xml' -o -name 'accounts.xml' -o -name 'policies.xml' \\) "
                "2>/dev/null | head -n 50 || true"
            ),
        )
        for line in out.splitlines():
            p = line.strip()
            if not p:
                continue
            found.append((p, _stat_mode(server, p)))

    if not found:
        if verbose:
            print("[WEB-03] 대상 비밀번호 파일(tomcat-users.xml/accounts.xml/policies.xml) 탐지 실패")
        return 2

    bad = []
    for path, mode in found:
        if verbose:
            print(f"[WEB-03] {path}: mode={oct(mode) if mode is not None else 'unknown'}")
        if mode is None:
            return 2
        if mode > 0o600:
            bad.append(path)

    return 0 if not bad else 1


def WEB_04(server: Server, *, verbose: bool = True) -> int:
    """
    WEB-04 웹 서비스 디렉터리 리스팅 방지 설정
    - 양호: 디렉터리 리스팅이 설정되지 않은 경우
    - 취약: 디렉터리 리스팅이 설정된 경우
    """

    if _is_windows(server):
        if verbose:
            print("[WEB-04] Windows(IIS) 환경은 수동 확인 필요(디렉터리 검색 기능)")
        return 2

    results: List[int] = []

    nginx_dirs = _nginx_dirs(server)
    if nginx_dirs:
        bad = _grep(server, r"^\s*autoindex\s+on\b", nginx_dirs)
        if verbose and bad.strip():
            print("[WEB-04] nginx autoindex on 감지:")
            print(bad.strip())
        results.append(1 if bad.strip() else 0)

    apache_dirs = _apache_dirs(server)
    if apache_dirs:
        lines = _grep(server, r"^\s*Options\b.*\bIndexes\b", apache_dirs)
        suspicious = []
        for line in lines.splitlines():
            if "-Indexes" in line or "Indexes-" in line:
                continue
            suspicious.append(line)
        if verbose and suspicious:
            print("[WEB-04] apache Indexes 활성 의심 라인:")
            for line in suspicious[:50]:
                print(line)
        results.append(1 if suspicious else 0)

    webxml_path, webxml = _read_first_existing(server, _tomcat_webxml_candidates())
    if webxml_path:
        if re.search(r"<param-name>\s*listings\s*</param-name>", webxml, re.IGNORECASE):
            if re.search(r"<param-value>\s*true\s*</param-value>", webxml, re.IGNORECASE):
                if verbose:
                    print(f"[WEB-04] tomcat listings=true 감지 ({webxml_path})")
                results.append(1)
            elif re.search(r"<param-value>\s*false\s*</param-value>", webxml, re.IGNORECASE):
                if verbose:
                    print(f"[WEB-04] tomcat listings=false 감지 ({webxml_path})")
                results.append(0)
            else:
                results.append(2)
        else:
            results.append(2)

    return _any_result(results)


def WEB_05(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-05] 수동 확인 필요: CGI/ISAPI 실행 제한(설정/운영 정책별 상이)")
    return 2


def WEB_06(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-06] 수동 확인 필요: 상위 디렉터리 접근 제한 설정(웹서버/애플리케이션 구성별 상이)")
    return 2


def WEB_07(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-07] 수동 확인 필요: 불필요한 파일 제거(서비스 구성/배포 정책별 상이)")
    return 2


def WEB_08(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-08] 수동 확인 필요: 업/다운로드 용량 제한(웹서버/애플리케이션 설정별 상이)")
    return 2


def WEB_09(server: Server, *, verbose: bool = True) -> int:
    """
    WEB-09 웹 서비스 프로세스 권한 제한
    - 양호: 서비스 프로세스가 일반 권한(비 root)로 동작
    - 취약: 서비스 프로세스가 root로 동작
    """

    if _is_windows(server):
        if verbose:
            print("[WEB-09] Windows 환경은 수동 확인 필요(IIS 서비스 계정)")
        return 2

    lines = _ps_list(server)
    if not lines:
        return 2

    targets = ("nginx", "apache2", "httpd", "tomcat", "catalina")
    matched: List[Tuple[str, str]] = []
    for line in lines:
        low = line.lower()
        if any(t in low for t in targets):
            parts = line.split(None, 2)
            if len(parts) >= 2:
                user = parts[0].strip()
                cmd = parts[1].strip()
                matched.append((user, cmd))

    if verbose and matched:
        for user, cmd in matched[:50]:
            print(f"[WEB-09] {user} {cmd}")

    if not matched:
        return 2

    has_non_root = any(user != "root" for user, _ in matched)
    all_root = all(user == "root" for user, _ in matched)

    if has_non_root:
        return 0
    return 1 if all_root else 2


def WEB_10(server: Server, *, verbose: bool = True) -> int:
    """
    WEB-10 불필요한 프록시 설정 제한
    - 양호: ProxyRequests Off(또는 미설정)
    - 취약: ProxyRequests On
    """

    if _is_windows(server):
        if verbose:
            print("[WEB-10] Windows(IIS) 환경은 수동 확인 필요(프록시 설정)")
        return 2

    apache_dirs = _apache_dirs(server)
    if not apache_dirs:
        return 2

    bad = _grep(server, r"^\s*ProxyRequests\s+On\b", apache_dirs)
    if verbose and bad.strip():
        print("[WEB-10] ProxyRequests On 감지:")
        print(bad.strip())
    return 1 if bad.strip() else 0


def WEB_11(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-11] 수동 확인 필요: 웹 서비스 경로 설정(서비스 구성별 상이)")
    return 2


def WEB_12(server: Server, *, verbose: bool = True) -> int:
    """
    WEB-12 웹 서비스 링크 사용 금지
    - 양호: 심볼릭 링크/aliases 사용 제한
    - 취약: 링크 사용 허용
    """

    if _is_windows(server):
        if verbose:
            print("[WEB-12] Windows(IIS) 환경은 수동 확인 필요(바로가기/가상 디렉터리 등)")
        return 2

    results: List[int] = []

    nginx_dirs = _nginx_dirs(server)
    if nginx_dirs:
        ok = _grep(server, r"^\s*disable_symlinks\s+on\b", nginx_dirs)
        if verbose and ok.strip():
            print("[WEB-12] nginx disable_symlinks on 감지:")
            print(ok.strip())
        results.append(0 if ok.strip() else 1)

    apache_dirs = _apache_dirs(server)
    if apache_dirs:
        found = _grep(server, r"^\s*Options\b.*\bFollowSymLinks\b", apache_dirs)
        enabled = []
        disabled = []
        for line in found.splitlines():
            if "-FollowSymLinks" in line:
                disabled.append(line)
            else:
                enabled.append(line)
        if verbose and (enabled or disabled):
            if enabled:
                print("[WEB-12] apache FollowSymLinks 활성 라인:")
                for line in enabled[:50]:
                    print(line)
            if disabled:
                print("[WEB-12] apache -FollowSymLinks 설정 라인:")
                for line in disabled[:50]:
                    print(line)
        if enabled:
            results.append(1)
        elif disabled:
            results.append(0)
        else:
            results.append(2)

    server_xml_path, server_xml = _read_first_existing(server, _tomcat_config_candidates())
    if server_xml_path:
        if re.search(r"allowLinking\\s*=\\s*\"true\"", server_xml, re.IGNORECASE):
            if verbose:
                print(f"[WEB-12] tomcat allowLinking=true 감지 ({server_xml_path})")
            results.append(1)
        else:
            results.append(0)

    return _any_result(results)


def WEB_13(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-13] 수동 확인 필요: 설정 파일 노출 제한(접근 제어 규칙/배포 방식별 상이)")
    return 2


def WEB_14(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-14] 수동 확인 필요: 웹 경로 내 파일 접근 통제(ACL/웹서버 설정별 상이)")
    return 2


def WEB_15(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-15] 수동 확인 필요: 불필요한 스크립트 매핑 제거(제품/프레임워크별 상이)")
    return 2


def WEB_16(server: Server, *, verbose: bool = True) -> int:
    """
    WEB-16 웹 서비스 헤더 정보 노출 제한
    - 양호: 버전 등 상세 정보 노출 제한
    - 취약: 버전 등 상세 정보 노출
    """

    if _is_windows(server):
        if verbose:
            print("[WEB-16] Windows(IIS) 환경은 수동 확인 필요(헤더/배너)")
        return 2

    head = _curl_head(server, "http://127.0.0.1")
    if head:
        server_hdr = _header_value(head, "Server")
        if verbose:
            print("[WEB-16] curl -I http://127.0.0.1:")
            print(head.strip())
        if server_hdr is not None:
            has_version = bool(re.search(r"(\\/\\d+)|(\\b\\d+\\.\\d+\\b)", server_hdr))
            return 1 if has_version else 0

    results: List[int] = []

    nginx_dirs = _nginx_dirs(server)
    if nginx_dirs:
        ok = _grep(server, r"^\s*server_tokens\s+off\b", nginx_dirs)
        results.append(0 if ok.strip() else 1)
        if verbose and ok.strip():
            print("[WEB-16] nginx server_tokens off 감지:")
            print(ok.strip())

    apache_dirs = _apache_dirs(server)
    if apache_dirs:
        tokens = _grep(server, r"^\s*ServerTokens\s+", apache_dirs)
        signature = _grep(server, r"^\s*ServerSignature\s+", apache_dirs)
        tokens_ok = bool(re.search(r"ServerTokens\\s+Prod\\b", tokens, re.IGNORECASE))
        signature_ok = bool(re.search(r"ServerSignature\\s+Off\\b", signature, re.IGNORECASE))
        if verbose:
            if tokens.strip():
                print("[WEB-16] apache ServerTokens:")
                print(tokens.strip())
            if signature.strip():
                print("[WEB-16] apache ServerSignature:")
                print(signature.strip())
        if tokens_ok and signature_ok:
            results.append(0)
        else:
            results.append(1)

    return _any_result(results)


def WEB_17(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-17] 수동 확인 필요: 불필요한 가상 디렉터리/샘플 제거 여부")
    return 2


def WEB_18(server: Server, *, verbose: bool = True) -> int:
    """
    WEB-18 WebDAV 비활성화
    - 양호: WebDAV 미사용/비활성화
    - 취약: WebDAV 활성화
    """

    if _is_windows(server):
        if verbose:
            print("[WEB-18] Windows(IIS) 환경은 수동 확인 필요(WebDAV 역할/기능)")
        return 2

    results: List[int] = []

    nginx_dirs = _nginx_dirs(server)
    if nginx_dirs:
        bad = _grep(server, r"\\bdav_methods\\b|\\bdav_access\\b", nginx_dirs)
        if verbose and bad.strip():
            print("[WEB-18] nginx WebDAV 관련 설정 감지:")
            print(bad.strip())
        results.append(1 if bad.strip() else 0)

    apache_dirs = _apache_dirs(server)
    if apache_dirs:
        bad = _grep(server, r"^\s*Dav\s+On\\b", apache_dirs)
        if verbose and bad.strip():
            print("[WEB-18] apache Dav On 감지:")
            print(bad.strip())
        results.append(1 if bad.strip() else 0)

    return _any_result(results)


def WEB_19(server: Server, *, verbose: bool = True) -> int:
    """
    WEB-19 SSI(Server Side Includes) 사용 제한
    - 양호: SSI 미사용/비활성화
    - 취약: SSI 활성화
    """

    if _is_windows(server):
        if verbose:
            print("[WEB-19] Windows(IIS) 환경은 수동 확인 필요(SSI 설정)")
        return 2

    results: List[int] = []

    nginx_dirs = _nginx_dirs(server)
    if nginx_dirs:
        bad = _grep(server, r"^\s*ssi\s+on\\b", nginx_dirs)
        if verbose and bad.strip():
            print("[WEB-19] nginx ssi on 감지:")
            print(bad.strip())
        results.append(1 if bad.strip() else 0)

    apache_dirs = _apache_dirs(server)
    if apache_dirs:
        bad1 = _grep(server, r"^\s*Options\\b.*\\bIncludes\\b", apache_dirs)
        bad2 = _grep(server, r"^\s*AddOutputFilter\\s+INCLUDES\\b", apache_dirs)
        if verbose and (bad1.strip() or bad2.strip()):
            print("[WEB-19] apache SSI 관련 설정 감지:")
            if bad1.strip():
                print(bad1.strip())
            if bad2.strip():
                print(bad2.strip())
        results.append(1 if (bad1.strip() or bad2.strip()) else 0)

    return _any_result(results)


def _is_port_listening(server: Server, port: int) -> Optional[bool]:
    if _command_exists(server, "ss"):
        out = _cmd(server, f"ss -lnt 2>/dev/null | grep -q ':{port} ' && echo 1 || echo 0")
        return out.strip() == "1"
    if _command_exists(server, "netstat"):
        out = _cmd(server, f"netstat -lnt 2>/dev/null | grep -q ':{port} ' && echo 1 || echo 0")
        return out.strip() == "1"
    return None


def WEB_20(server: Server, *, verbose: bool = True) -> int:
    """
    WEB-20 SSL/TLS 활성화
    - 양호: HTTPS(443) 활성
    - 취약: 비활성
    """

    listening = _is_port_listening(server, 443)
    if listening is None:
        if verbose:
            print("[WEB-20] 포트 상태 확인 불가(수동 확인 필요)")
        return 2
    if verbose:
        print(f"[WEB-20] port 443 listening={listening}")
    return 0 if listening else 1


def WEB_21(server: Server, *, verbose: bool = True) -> int:
    """
    WEB-21 HTTP 리디렉션
    - 양호: HTTP -> HTTPS 리디렉션
    - 취약: 미적용
    """

    head = _curl_head(server, "http://127.0.0.1")
    if not head:
        if verbose:
            print("[WEB-21] curl 미사용 또는 HTTP 응답 확인 실패(수동 확인 필요)")
        return 2

    status = _first_http_status(head)
    location = _header_value(head, "Location")
    if verbose:
        print("[WEB-21] curl -I http://127.0.0.1:")
        print(head.strip())
        print(f"[WEB-21] status={status!r}, location={location!r}")
    if status in {301, 302, 303, 307, 308} and location and location.lower().startswith("https://"):
        return 0
    return 1


def WEB_22(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-22] 수동 확인 필요: 에러 페이지 관리(커스텀 에러/정보 노출 여부)")
    return 2


def WEB_23(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-23] 수동 확인 필요: LDAP 알고리즘 구성(인증 연동/정책별 상이)")
    return 2


def WEB_24(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-24] 수동 확인 필요: 별도 업로드 경로 사용 및 권한 설정(애플리케이션별 상이)")
    return 2


def WEB_25(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[WEB-25] 수동 확인 필요: 보안 패치 및 벤더 권고사항 적용 절차/주기")
    return 2


def WEB_26(server: Server, *, verbose: bool = True) -> int:
    """
    WEB-26 로그 디렉터리 및 파일 권한 설정
    - 양호: 로그 디렉터리/파일에 일반 사용자(other)의 접근 권한이 없는 경우
    - 취약: other 권한이 존재하는 경우
    """

    if _is_windows(server):
        if verbose:
            print("[WEB-26] Windows(IIS) 환경은 수동 확인 필요(로그 경로/ACL)")
        return 2

    log_dirs = _existing_dirs(
        server,
        [
            "/var/log/nginx",
            "/var/log/apache2",
            "/var/log/httpd",
            "/var/log/tomcat",
            "/var/log/tomcat9",
            "/opt/tomcat/logs",
            "/usr/local/tomcat/logs",
            "/home/tmax/webtob/log",
        ],
    )
    if not log_dirs:
        if verbose:
            print("[WEB-26] 로그 디렉터리 탐지 실패(수동 확인 필요)")
        return 2

    bad: List[Tuple[str, int]] = []
    checked = 0
    for d in log_dirs:
        entries = _cmd(server, f"ls -1A {_q(d)} 2>/dev/null | head -n 50 || true").splitlines()
        paths = [d] + [f"{d}/{e.strip()}" for e in entries if e.strip()]
        for p in paths:
            mode = _stat_mode(server, p)
            if mode is None:
                continue
            checked += 1
            if verbose:
                print(f"[WEB-26] {p}: mode={oct(mode)}")
            if mode & 0o007:
                bad.append((p, mode))

    if checked == 0:
        return 2
    if bad and verbose:
        print("[WEB-26] 일반 사용자(other) 권한이 존재하는 항목:")
        for p, mode in bad[:50]:
            print(f"  - {p}: {oct(mode)}")
    return 0 if not bad else 1


CHECKS: Dict[str, Callable[..., int]] = {
    "WEB-01": WEB_01,
    "WEB-02": WEB_02,
    "WEB-03": WEB_03,
    "WEB-04": WEB_04,
    "WEB-05": WEB_05,
    "WEB-06": WEB_06,
    "WEB-07": WEB_07,
    "WEB-08": WEB_08,
    "WEB-09": WEB_09,
    "WEB-10": WEB_10,
    "WEB-11": WEB_11,
    "WEB-12": WEB_12,
    "WEB-13": WEB_13,
    "WEB-14": WEB_14,
    "WEB-15": WEB_15,
    "WEB-16": WEB_16,
    "WEB-17": WEB_17,
    "WEB-18": WEB_18,
    "WEB-19": WEB_19,
    "WEB-20": WEB_20,
    "WEB-21": WEB_21,
    "WEB-22": WEB_22,
    "WEB-23": WEB_23,
    "WEB-24": WEB_24,
    "WEB-25": WEB_25,
    "WEB-26": WEB_26,
}
