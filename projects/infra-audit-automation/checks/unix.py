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


def _exists(server: Server, path: str) -> bool:
    return _cmd(server, f"test -e {_q(path)} && echo 1 || echo 0") == "1"


def _read(server: Server, path: str) -> str:
    return _cmd(server, f"cat {_q(path)} 2>/dev/null || true")


def _command_exists(server: Server, name: str) -> bool:
    return _cmd(server, f"command -v {_q(name)} >/dev/null 2>&1 && echo 1 || echo 0") == "1"


def _iter_active_lines(text: str) -> Iterable[str]:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        yield line


def _config_value(text: str, key: str) -> Optional[str]:
    key_lower = key.lower()
    for line in _iter_active_lines(text):
        if "=" in line:
            k, v = line.split("=", 1)
            if k.strip().lower() == key_lower:
                return v.strip().strip('"')
        parts = line.split(None, 1)
        if parts and parts[0].strip().lower() == key_lower:
            return parts[1].strip() if len(parts) > 1 else ""
    return None


def _parse_kv(text: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in _iter_active_lines(text):
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k.strip().lower()] = v.strip().strip('"')
    return data


def _extract_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except Exception:
        return None


def _extract_login_defs_value(text: str, key: str) -> Optional[str]:
    for line in _iter_active_lines(text):
        parts = line.split()
        if len(parts) >= 2 and parts[0] == key:
            return parts[1].strip()
    return None


def _pam_extract_int(pam_text: str, key: str) -> Optional[int]:
    if not pam_text:
        return None
    m = re.search(rf"\b{re.escape(key)}=(?P<v>-?\d+)\b", pam_text)
    if not m:
        return None
    return _extract_int(m.group("v"))


def _stat_user_mode(server: Server, path: str) -> Tuple[Optional[str], Optional[int]]:
    if not _exists(server, path):
        return None, None
    if _command_exists(server, "stat"):
        out = _cmd(server, f"stat -c '%U %a' {_q(path)} 2>/dev/null || true").strip()
        if out:
            parts = out.split()
            if len(parts) >= 2:
                user = parts[0].strip()
                try:
                    mode = int(parts[1], 8)
                except ValueError:
                    mode = None
                return user, mode
    out = _cmd(server, f"ls -ld {_q(path)} 2>/dev/null || true").strip()
    if not out:
        return None, None
    parts = out.split()
    if len(parts) < 3:
        return None, None
    perm = parts[0]
    user = parts[2]
    mode = _permstr_to_mode(perm)
    return user, mode


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


def _check_file_owner_mode(
    server: Server,
    path: str,
    *,
    owners: Sequence[str],
    max_mode: int,
    verbose: bool,
    label: str,
) -> Optional[int]:
    owner, mode = _stat_user_mode(server, path)
    if owner is None or mode is None:
        return None
    ok = owner in owners and mode <= max_mode
    if not ok and verbose:
        print(f"[{label}] {path} owner={owner}, mode={oct(mode)} (권고: {owners}, {oct(max_mode)} 이하)")
    return 0 if ok else 1


def _systemctl_active(server: Server, unit: str) -> bool:
    if not _command_exists(server, "systemctl"):
        return False
    out = _cmd(server, f"systemctl is-active {_q(unit)} 2>/dev/null || true").strip().lower()
    return out == "active"


def _is_port_listening(server: Server, port: int) -> bool:
    if _command_exists(server, "ss"):
        return _cmd(server, f"ss -lnt 2>/dev/null | grep -q ':{port} ' && echo 1 || echo 0") == "1"
    if _command_exists(server, "netstat"):
        return _cmd(server, f"netstat -lnt 2>/dev/null | grep -q ':{port} ' && echo 1 || echo 0") == "1"
    return False


def _ps_has(server: Server, pattern: str) -> bool:
    cmd = f"ps -ef 2>/dev/null | grep -E {_q(pattern)} | grep -v grep >/dev/null 2>&1 && echo 1 || echo 0"
    return _cmd(server, cmd) == "1"


def _get_passwd_entries(server: Server) -> List[Tuple[str, str, str, str, str]]:
    text = _read(server, "/etc/passwd")
    entries: List[Tuple[str, str, str, str, str]] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        user, _pw, uid, gid, _gecos, home, shell = parts[:7]
        entries.append((user, uid, gid, home, shell))
    return entries


def _get_group_gid_set(server: Server) -> set[str]:
    text = _read(server, "/etc/group")
    gids: set[str] = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        gids.add(parts[2])
    return gids


def _inetd_enabled(server: Server, services: Sequence[str]) -> bool:
    path = "/etc/inetd.conf"
    if not _exists(server, path):
        return False
    text = _read(server, path)
    targets = set(services)
    for line in _iter_active_lines(text):
        parts = line.split()
        if parts and parts[0] in targets:
            return True
    return False


def _xinetd_service_enabled(server: Server, name: str) -> Optional[bool]:
    path = f"/etc/xinetd.d/{name}"
    if not _exists(server, path):
        return None
    text = _read(server, path)
    disable_val = None
    for line in _iter_active_lines(text):
        if line.lower().startswith("disable") and "=" in line:
            disable_val = line.split("=", 1)[1].strip().lower()
    if disable_val is None:
        return True
    return disable_val in {"no", "false", "0"}


def _is_login_shell(shell: str) -> bool:
    shell = shell.strip()
    if not shell:
        return False
    return shell not in {"/bin/false", "/usr/bin/false", "/sbin/nologin", "/usr/sbin/nologin"}


def _mail_running(server: Server) -> bool:
    if _is_port_listening(server, 25):
        return True
    for svc in ("postfix", "sendmail", "exim", "exim4"):
        if _systemctl_active(server, svc):
            return True
    return False


def _dns_running(server: Server) -> bool:
    if _is_port_listening(server, 53):
        return True
    for svc in ("named", "bind9"):
        if _systemctl_active(server, svc):
            return True
    return False


def _ftp_running(server: Server) -> bool:
    if _is_port_listening(server, 21):
        return True
    for svc in ("vsftpd", "proftpd", "pure-ftpd"):
        if _systemctl_active(server, svc):
            return True
    return False


def _snmp_running(server: Server) -> bool:
    return _systemctl_active(server, "snmpd") or _ps_has(server, r"\bsnmpd\b") or _is_port_listening(server, 161)


def _read_first(server: Server, paths: Sequence[str]) -> str:
    for p in paths:
        if _exists(server, p):
            return _read(server, p)
    return ""


def _snmp_conf(server: Server) -> str:
    return _read_first(server, ["/etc/snmp/snmpd.conf", "/etc/snmp/conf/snmpd.conf", "/etc/snmpd.conf"])


def U_01(server: Server, *, verbose: bool = True) -> int:
    cfg_path = "/etc/ssh/sshd_config"
    if _exists(server, cfg_path):
        cfg = _read(server, cfg_path)
        val = _config_value(cfg, "PermitRootLogin")
        if val is None:
            if verbose:
                print("[U-01] PermitRootLogin 설정 없음")
            return 1
        val0 = (val.split() or [""])[0].lower()
        return 0 if val0 == "no" else 1

    if _systemctl_active(server, "sshd") or _systemctl_active(server, "ssh") or _is_port_listening(server, 22):
        if verbose:
            print("[U-01] sshd 실행 중이나 설정 파일 확인 불가")
        return 1
    return 0


def U_02(server: Server, *, verbose: bool = True) -> int:
    login_defs = _read(server, "/etc/login.defs") if _exists(server, "/etc/login.defs") else ""
    pass_min_days = _extract_int(_extract_login_defs_value(login_defs, "PASS_MIN_DAYS"))
    pass_max_days = _extract_int(_extract_login_defs_value(login_defs, "PASS_MAX_DAYS"))

    pwq_text = _read_first(server, ["/etc/security/pwquality.conf", "/etc/pwquality.conf"])
    pwq = _parse_kv(pwq_text) if pwq_text else {}

    pam_text = "\n".join(
        _read(server, p)
        for p in ("/etc/pam.d/system-auth", "/etc/pam.d/password-auth", "/etc/pam.d/common-password")
        if _exists(server, p)
    )

    minlen = _extract_int(pwq.get("minlen")) or _pam_extract_int(pam_text, "minlen")
    dcredit = _extract_int(pwq.get("dcredit")) or _pam_extract_int(pam_text, "dcredit")
    ucredit = _extract_int(pwq.get("ucredit")) or _pam_extract_int(pam_text, "ucredit")
    lcredit = _extract_int(pwq.get("lcredit")) or _pam_extract_int(pam_text, "lcredit")
    ocredit = _extract_int(pwq.get("ocredit")) or _pam_extract_int(pam_text, "ocredit")
    remember = _pam_extract_int(pam_text, "remember")

    needed = {
        "PASS_MIN_DAYS": pass_min_days,
        "PASS_MAX_DAYS": pass_max_days,
        "minlen": minlen,
        "dcredit": dcredit,
        "ucredit": ucredit,
        "lcredit": lcredit,
        "ocredit": ocredit,
        "remember": remember,
    }
    if any(v is None for v in needed.values()):
        if verbose:
            missing = ", ".join(k for k, v in needed.items() if v is None)
            print(f"[U-02] 일부 설정값 확인 불가({missing}) → 수동 확인")
        return 2

    ok = (
        minlen >= 8
        and pass_min_days >= 1
        and pass_max_days <= 90
        and remember >= 4
        and dcredit <= -1
        and ucredit <= -1
        and lcredit <= -1
        and ocredit <= -1
    )
    return 0 if ok else 1


def U_03(server: Server, *, verbose: bool = True) -> int:
    pam_text = "\n".join(
        _read(server, p)
        for p in ("/etc/pam.d/system-auth", "/etc/pam.d/password-auth", "/etc/pam.d/common-auth")
        if _exists(server, p)
    )
    deny = _pam_extract_int(pam_text, "deny")
    if deny is None:
        return 1
    return 0 if deny <= 10 else 1


def U_04(server: Server, *, verbose: bool = True) -> int:
    passwd = _read(server, "/etc/passwd")
    bad: List[str] = []
    for line in passwd.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        user, pw_field = parts[0], parts[1]
        if not pw_field:
            continue
        if pw_field in {"x", "*", "!", "!!"}:
            continue
        bad.append(user)
    if bad and verbose:
        print(f"[U-04] /etc/passwd에 비밀번호 필드 노출 계정: {', '.join(bad[:10])}")
    return 1 if bad else 0


def U_05(server: Server, *, verbose: bool = True) -> int:
    passwd = _read(server, "/etc/passwd")
    uid0 = []
    for line in passwd.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 3 and parts[2] == "0":
            uid0.append(parts[0])
    if len(uid0) <= 1:
        return 0
    if verbose:
        print(f"[U-05] UID 0 계정 다수: {', '.join(uid0)}")
    return 1


def U_06(server: Server, *, verbose: bool = True) -> int:
    pam_su = _read(server, "/etc/pam.d/su") if _exists(server, "/etc/pam.d/su") else ""
    pam_wheel = any("pam_wheel.so" in ln for ln in _iter_active_lines(pam_su))

    su_path = "/usr/bin/su" if _exists(server, "/usr/bin/su") else ("/bin/su" if _exists(server, "/bin/su") else "")
    if not su_path:
        return 2

    owner, mode = _stat_user_mode(server, su_path)
    if owner is None or mode is None:
        return 2

    file_ok = owner == "root" and bool(mode & 0o4000) and not bool(mode & 0o0001)
    if pam_wheel:
        return 0 if file_ok else 1

    if owner != "root":
        return 1
    return 0 if file_ok and (mode & 0o777) <= 0o750 else 1


def U_07(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[U-07] 불필요 계정 판단은 운영 기준 필요 → 증거만 수집")
        print(_cmd(server, "cut -d: -f1,3,6,7 /etc/passwd 2>/dev/null | head -n 50"))
        last = _cmd(server, "last -n 20 2>/dev/null || true")
        if last:
            print(last)
    return 2


def U_08(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[U-08] 관리자 그룹 최소 포함 여부는 기준 필요 → 증거만 수집")
        print(_cmd(server, "getent group wheel sudo adm 2>/dev/null || true"))
    return 2


def U_09(server: Server, *, verbose: bool = True) -> int:
    gids = _get_group_gid_set(server)
    missing = [(u, g) for u, _uid, g, _h, _s in _get_passwd_entries(server) if g not in gids]
    if missing and verbose:
        print("[U-09] /etc/group에 없는 GID 사용:", ", ".join(f"{u}(gid={g})" for u, g in missing[:10]))
    return 1 if missing else 0


def U_10(server: Server, *, verbose: bool = True) -> int:
    seen: Dict[str, str] = {}
    dup: List[Tuple[str, str, str]] = []
    for user, uid, _gid, _home, _shell in _get_passwd_entries(server):
        if uid in seen:
            dup.append((uid, seen[uid], user))
        else:
            seen[uid] = user
    if dup and verbose:
        print("[U-10] 동일 UID:", ", ".join(f"uid={uid}:{a},{b}" for uid, a, b in dup[:10]))
    return 1 if dup else 0


def U_11(server: Server, *, verbose: bool = True) -> int:
    targets = {
        "daemon",
        "bin",
        "sys",
        "adm",
        "listen",
        "nobody",
        "nobody4",
        "noaccess",
        "diag",
        "operator",
        "games",
        "gopher",
    }
    allowed_shells = {"/bin/false", "/usr/bin/false", "/sbin/nologin", "/usr/sbin/nologin"}
    bad = [(u, sh) for u, _uid, _gid, _h, sh in _get_passwd_entries(server) if u in targets and sh.strip() not in allowed_shells]
    if bad and verbose:
        print("[U-11] 로그인 불필요 계정에 로그인 셸 부여:", ", ".join(f"{u}:{sh}" for u, sh in bad[:10]))
    return 1 if bad else 0


def U_12(server: Server, *, verbose: bool = True) -> int:
    tmout = None
    for shell in ("bash", "sh"):
        if _command_exists(server, shell):
            out = _cmd(server, f"{shell} -lc 'echo ${{TMOUT:-}}' 2>/dev/null || true").strip()
            if out.isdigit():
                tmout = int(out)
                break
    if tmout is not None:
        return 0 if tmout <= 600 else 1

    grep_out = _cmd(server, "(grep -R -n -E '^[[:space:]]*TMOUT=' /etc/profile /etc/profile.d 2>/dev/null || true) | head -n 20")
    m = re.search(r"TMOUT=([0-9]+)", grep_out)
    if m:
        return 0 if int(m.group(1)) <= 600 else 1
    return 1


def U_13(server: Server, *, verbose: bool = True) -> int:
    login_defs = _read(server, "/etc/login.defs") if _exists(server, "/etc/login.defs") else ""
    method = (_extract_login_defs_value(login_defs, "ENCRYPT_METHOD") or "").lower()
    if method:
        return 0 if method in {"sha256", "sha512", "yescrypt"} else 1

    pam_text = "\n".join(_read(server, p) for p in ("/etc/pam.d/system-auth", "/etc/pam.d/common-password") if _exists(server, p))
    if re.search(r"pam_unix\.so.*\b(sha512|sha256|yescrypt)\b", pam_text):
        return 0

    shadow = _read(server, "/etc/shadow") if _exists(server, "/etc/shadow") else ""
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        pw = parts[1]
        if not pw or pw in {"*", "!", "!!"}:
            continue
        if pw.startswith(("$6$", "$5$", "$y$")):
            return 0
        if pw.startswith("$1$"):
            return 1
        break
    return 2


def U_14(server: Server, *, verbose: bool = True) -> int:
    path_val = ""
    for shell in ("bash", "sh"):
        if _command_exists(server, shell):
            path_val = _cmd(server, f"{shell} -lc 'echo $PATH' 2>/dev/null || true").strip()
            if path_val:
                break
    if not path_val:
        return 2
    parts = [p if p else "." for p in path_val.split(":")]
    dot_pos = [i for i, p in enumerate(parts) if p == "."]
    if not dot_pos:
        return 0
    last = len(parts) - 1
    return 0 if all(i == last for i in dot_pos) else 1


def U_15(server: Server, *, verbose: bool = True) -> int:
    first = _cmd(server, "find / \\( -nouser -o -nogroup \\) -xdev -print -quit 2>/dev/null || true").strip()
    if not first:
        return 0
    if verbose:
        print(f"[U-15] 소유자/그룹 없음: {first}")
    return 1


def U_16(server: Server, *, verbose: bool = True) -> int:
    res = _check_file_owner_mode(server, "/etc/passwd", owners=["root"], max_mode=0o644, verbose=verbose, label="U-16")
    return 2 if res is None else res


def U_17(server: Server, *, verbose: bool = True) -> int:
    dirs = ["/etc/init.d", "/etc/rc.d/init.d", "/etc/systemd/system"]
    if not any(_exists(server, d) for d in dirs):
        return 2
    for d in dirs:
        if not _exists(server, d):
            continue
        first = _cmd(server, f"find {_q(d)} -xdev -type f \\( ! -user root -o -perm -0002 \\) -print -quit 2>/dev/null || true").strip()
        if first:
            return 1
    return 0


def U_18(server: Server, *, verbose: bool = True) -> int:
    for p in ("/etc/shadow", "/etc/security/passwd"):
        if not _exists(server, p):
            continue
        res = _check_file_owner_mode(server, p, owners=["root"], max_mode=0o400, verbose=verbose, label="U-18")
        return 2 if res is None else res
    return 2


def U_19(server: Server, *, verbose: bool = True) -> int:
    res = _check_file_owner_mode(server, "/etc/hosts", owners=["root"], max_mode=0o644, verbose=verbose, label="U-19")
    return 2 if res is None else res


def U_20(server: Server, *, verbose: bool = True) -> int:
    paths = ["/etc/inetd.conf", "/etc/xinetd.conf"]
    if not any(_exists(server, p) for p in paths):
        return 0
    for p in paths:
        if not _exists(server, p):
            continue
        res = _check_file_owner_mode(server, p, owners=["root"], max_mode=0o600, verbose=verbose, label="U-20")
        if res == 1:
            return 1
        if res is None:
            return 2
    return 0


def U_21(server: Server, *, verbose: bool = True) -> int:
    target = next((p for p in ("/etc/rsyslog.conf", "/etc/syslog.conf") if _exists(server, p)), None)
    if not target:
        return 0
    res = _check_file_owner_mode(server, target, owners=["root", "bin", "sys"], max_mode=0o640, verbose=verbose, label="U-21")
    return 2 if res is None else res


def U_22(server: Server, *, verbose: bool = True) -> int:
    res = _check_file_owner_mode(server, "/etc/services", owners=["root", "bin", "sys"], max_mode=0o644, verbose=verbose, label="U-22")
    return 2 if res is None else res


def U_23(server: Server, *, verbose: bool = True) -> int:
    out = _cmd(server, "find / -user root -type f \\( -perm -04000 -o -perm -02000 \\) -xdev -print 2>/dev/null | head -n 50").strip()
    if not out:
        return 0
    if verbose:
        print("[U-23] SUID/SGID 파일 목록(상위 50개) → 수동 검토")
        print(out)
    return 2


def U_24(server: Server, *, verbose: bool = True) -> int:
    env_files = [".profile", ".kshrc", ".cshrc", ".bashrc", ".bash_profile", ".login", ".exrc", ".netrc"]
    bad = []
    for user, _uid, _gid, home, _shell in _get_passwd_entries(server):
        home = home.strip()
        if not home or home in {"/", "/nonexistent"} or not _exists(server, home):
            continue
        for name in env_files:
            path = f"{home}/{name}"
            if not _exists(server, path):
                continue
            owner, mode = _stat_user_mode(server, path)
            if owner is None or mode is None:
                continue
            if owner not in {"root", user} or (mode & 0o002):
                bad.append(path)
    if bad and verbose:
        print("[U-24] 환경변수 파일 소유자/권한 취약 후보:", ", ".join(bad[:10]))
    return 1 if bad else 0


def U_25(server: Server, *, verbose: bool = True) -> int:
    first = _cmd(server, "find / -type f -perm -0002 -xdev -print -quit 2>/dev/null || true").strip()
    if not first:
        return 0
    if verbose:
        print(f"[U-25] world writable 파일 존재(사유 수동 확인): {first}")
    return 2


def U_26(server: Server, *, verbose: bool = True) -> int:
    first = _cmd(server, "find /dev -type f -xdev -print -quit 2>/dev/null || true").strip()
    if not first:
        return 0
    if verbose:
        print(f"[U-26] /dev 내 일반 파일: {first}")
    return 1


def U_27(server: Server, *, verbose: bool = True) -> int:
    if _exists(server, "/etc/hosts.equiv"):
        return 1
    for _u, _uid, _gid, home, _shell in _get_passwd_entries(server):
        home = home.strip()
        if not home or not _exists(server, home):
            continue
        found = _cmd(server, f"find {_q(home)} -maxdepth 2 -name .rhosts -print -quit 2>/dev/null || true").strip()
        if found:
            return 1
    return 0


def U_28(server: Server, *, verbose: bool = True) -> int:
    deny = _read(server, "/etc/hosts.deny") if _exists(server, "/etc/hosts.deny") else ""
    allow = _read(server, "/etc/hosts.allow") if _exists(server, "/etc/hosts.allow") else ""
    has_all_deny = any(re.fullmatch(r"ALL\s*:\s*ALL", ln, flags=re.I) for ln in _iter_active_lines(deny))
    has_any_allow = any(True for _ in _iter_active_lines(allow))
    if has_all_deny and has_any_allow:
        return 0
    if verbose:
        print("[U-28] 접근 IP/포트 제한(방화벽/TCP Wrapper) 설정은 수동 확인 필요")
    return 2


def U_29(server: Server, *, verbose: bool = True) -> int:
    path = "/etc/hosts.lpd"
    if not _exists(server, path):
        return 0
    res = _check_file_owner_mode(server, path, owners=["root"], max_mode=0o600, verbose=verbose, label="U-29")
    return 2 if res is None else res


def U_30(server: Server, *, verbose: bool = True) -> int:
    umask_val: Optional[int] = None
    if _command_exists(server, "bash"):
        out = _cmd(server, "bash -lc 'umask' 2>/dev/null || true").strip()
        if re.fullmatch(r"[0-7]{3,4}", out):
            umask_val = int(out, 8)

    if umask_val is None and _exists(server, "/etc/login.defs"):
        raw = _extract_login_defs_value(_read(server, "/etc/login.defs"), "UMASK")
        if raw and re.fullmatch(r"[0-7]{3,4}", raw):
            umask_val = int(raw, 8)

    if umask_val is None and _exists(server, "/etc/profile"):
        prof = _read(server, "/etc/profile")
        m = re.search(r"\bumask\s+([0-7]{3,4})\b", prof)
        if m:
            umask_val = int(m.group(1), 8)

    if umask_val is None:
        return 2
    return 0 if umask_val >= 0o022 else 1


def U_31(server: Server, *, verbose: bool = True) -> int:
    bad = []
    for user, _uid, _gid, home, shell in _get_passwd_entries(server):
        if not _is_login_shell(shell):
            continue
        home = home.strip()
        if not home or home == "/" or not _exists(server, home):
            continue
        owner, mode = _stat_user_mode(server, home)
        if owner is None or mode is None:
            continue
        if owner != user or (mode & 0o002):
            bad.append(f"{user}:{home}")
    if bad and verbose:
        print("[U-31] 홈디렉토리 소유자/권한 취약 후보:", ", ".join(bad[:10]))
    return 1 if bad else 0


def U_32(server: Server, *, verbose: bool = True) -> int:
    missing = []
    for user, _uid, _gid, home, shell in _get_passwd_entries(server):
        if not _is_login_shell(shell):
            continue
        home = home.strip()
        if not home or home == "/" or _exists(server, home):
            continue
        missing.append(f"{user}:{home}")
    if missing and verbose:
        print("[U-32] 홈디렉토리 미존재 계정:", ", ".join(missing[:10]))
    return 1 if missing else 0


def U_33(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[U-33] 숨김 파일/디렉터리 불필요/의심 여부는 수동 판단")
        print(_cmd(server, "find / -xdev -name '.*' -maxdepth 3 -print 2>/dev/null | head -n 50"))
    return 2


def U_34(server: Server, *, verbose: bool = True) -> int:
    if _inetd_enabled(server, ["finger"]):
        return 1
    if _xinetd_service_enabled(server, "finger") is True:
        return 1
    return 1 if _is_port_listening(server, 79) else 0


def U_35(server: Server, *, verbose: bool = True) -> int:
    vs_cfg = _read_first(server, ["/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf"])
    if vs_cfg:
        v = (_config_value(vs_cfg, "anonymous_enable") or "").lower()
        if v in {"yes", "true", "1"}:
            return 1

    pro_cfg = _read_first(server, ["/etc/proftpd.conf", "/etc/proftpd/proftpd.conf"])
    if pro_cfg and (re.search(r"^\s*<Anonymous\b", pro_cfg, flags=re.M) or re.search(r"^\s*UserAlias\s+anonymous\b", pro_cfg, flags=re.M)):
        return 1

    passwd = _read(server, "/etc/passwd")
    if re.search(r"^anonymous:", passwd, flags=re.M):
        return 1

    for p in ("/etc/dfs/dfstab", "/etc/exports"):
        if not _exists(server, p):
            continue
        text = _read(server, p)
        if re.search(r"\banon\s*=\s*(?!-1)\d+", text) or re.search(r"\banonuid\s*=\s*(?!-1)\d+", text):
            return 1

    return 0


def U_36(server: Server, *, verbose: bool = True) -> int:
    if _inetd_enabled(server, ["shell", "login", "exec"]):
        return 1
    for svc in ("rsh", "rlogin", "rexec"):
        if _xinetd_service_enabled(server, svc) is True:
            return 1
    return 1 if any(_is_port_listening(server, p) for p in (512, 513, 514)) else 0


def U_37(server: Server, *, verbose: bool = True) -> int:
    for b in ("/usr/bin/crontab", "/usr/bin/at"):
        if not _exists(server, b):
            continue
        owner, mode = _stat_user_mode(server, b)
        if owner is None or mode is None:
            return 2
        if owner != "root" or mode > 0o750:
            return 1

    for p in ("/etc/crontab", "/etc/cron.allow", "/etc/cron.deny", "/etc/at.allow", "/etc/at.deny"):
        if not _exists(server, p):
            continue
        owner, mode = _stat_user_mode(server, p)
        if owner is None or mode is None:
            return 2
        if owner != "root" or mode > 0o640:
            return 1

    for d in ("/etc/cron.d", "/var/spool/cron", "/var/spool/at"):
        if not _exists(server, d):
            continue
        first = _cmd(server, f"find {_q(d)} -xdev -type f -perm -0002 -print -quit 2>/dev/null || true").strip()
        if first:
            return 1
    return 0


def U_38(server: Server, *, verbose: bool = True) -> int:
    if _inetd_enabled(server, ["echo", "discard", "daytime", "chargen"]):
        return 1
    for svc in ("echo", "discard", "daytime", "chargen"):
        if _xinetd_service_enabled(server, svc) is True:
            return 1
    return 0


def U_39(server: Server, *, verbose: bool = True) -> int:
    active = [svc for svc in ("nfs-server", "nfs", "rpcbind", "rpc-statd") if _systemctl_active(server, svc)]
    if not active:
        return 0
    if verbose:
        print("[U-39] NFS 관련 서비스 활성(불필요 여부 수동 확인):", ", ".join(active))
    return 2


def U_40(server: Server, *, verbose: bool = True) -> int:
    exports_path = "/etc/exports"
    nfs_active = any(_systemctl_active(server, svc) for svc in ("nfs-server", "nfs"))
    if not _exists(server, exports_path):
        return 0 if not nfs_active else 2

    res = _check_file_owner_mode(server, exports_path, owners=["root"], max_mode=0o644, verbose=verbose, label="U-40")
    if res in {1, 2}:
        return 1 if res == 1 else 2

    exports = _read(server, exports_path)
    lines = list(_iter_active_lines(exports))
    if not lines:
        return 0 if not nfs_active else 2

    for ln in lines:
        parts = ln.split()
        if len(parts) < 2:
            continue
        clients = parts[1:]
        if any(c in {"*", "0.0.0.0/0", "0.0.0.0", "::/0"} or c.startswith("*.") for c in clients):
            return 1
    return 0


def U_41(server: Server, *, verbose: bool = True) -> int:
    return 1 if (_systemctl_active(server, "autofs") or _systemctl_active(server, "automount") or _ps_has(server, r"\bautomountd\b")) else 0


def U_42(server: Server, *, verbose: bool = True) -> int:
    pattern = r"rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd"
    return 1 if _ps_has(server, pattern) else 0


def U_43(server: Server, *, verbose: bool = True) -> int:
    return 1 if (_ps_has(server, r"\b(ypserv|ypbind|rpc\.nisd|nisd)\b") or _systemctl_active(server, "ypserv") or _systemctl_active(server, "ypbind")) else 0


def U_44(server: Server, *, verbose: bool = True) -> int:
    if _inetd_enabled(server, ["tftp", "talk", "ntalk"]):
        return 1
    for svc in ("tftp", "talk", "ntalk"):
        if _xinetd_service_enabled(server, svc) is True:
            return 1
    return 0


def U_45(server: Server, *, verbose: bool = True) -> int:
    if not _mail_running(server):
        return 0
    if verbose:
        print("[U-45] 메일 서비스 버전 최신 여부는 수동 비교 필요")
        if _command_exists(server, "postconf"):
            print(_cmd(server, "postconf mail_version 2>/dev/null || true"))
        if _command_exists(server, "sendmail"):
            print(_cmd(server, "sendmail -d0.1 -bv root 2>/dev/null | head -n 5"))
        if _command_exists(server, "exim"):
            print(_cmd(server, "exim -bV 2>/dev/null | head -n 5"))
    return 2


def U_46(server: Server, *, verbose: bool = True) -> int:
    ok = True
    if _exists(server, "/etc/mail/sendmail.cf"):
        text = _read(server, "/etc/mail/sendmail.cf")
        m = re.search(r"^\s*PrivacyOptions\s*=\s*(.+)$", text, flags=re.M)
        if not m or "restrictqrun" not in m.group(1):
            ok = False

    for path in ("/usr/sbin/postsuper", "/usr/sbin/exiqgrep"):
        if not _exists(server, path):
            continue
        owner, mode = _stat_user_mode(server, path)
        if owner is None or mode is None:
            return 2
        if mode & 0o001:
            ok = False
    return 0 if ok else 1


def U_47(server: Server, *, verbose: bool = True) -> int:
    if not _mail_running(server):
        return 0
    if _systemctl_active(server, "postfix") or _exists(server, "/etc/postfix/main.cf"):
        cfg = _read(server, "/etc/postfix/main.cf") if _exists(server, "/etc/postfix/main.cf") else ""
        if re.search(r"\breject_unauth_destination\b", cfg):
            mynet = _config_value(cfg, "mynetworks") or ""
            if any(tok in mynet for tok in ("0.0.0.0/0", "0.0.0.0", "::/0")):
                return 1
            return 0
        return 2
    return 2


def U_48(server: Server, *, verbose: bool = True) -> int:
    if not _mail_running(server):
        return 0

    if _exists(server, "/etc/mail/sendmail.cf"):
        text = _read(server, "/etc/mail/sendmail.cf")
        m = re.search(r"^\s*PrivacyOptions\s*=\s*(.+)$", text, flags=re.M)
        if not m:
            return 1
        opts = m.group(1)
        return 0 if ("goaway" in opts or ("noexpn" in opts and "novrfy" in opts)) else 1

    if _exists(server, "/etc/postfix/main.cf"):
        text = _read(server, "/etc/postfix/main.cf")
        v = (_config_value(text, "disable_vrfy_command") or "").lower()
        return 0 if v in {"yes", "true", "1"} else 1

    exim_cf = next((p for p in ("/etc/exim/exim.conf", "/etc/exim4/exim4.conf") if _exists(server, p)), None)
    if exim_cf:
        text = _read(server, exim_cf)
        if re.search(r"^\s*acl_smtp_vrfy\s*=\s*accept\b", text, flags=re.M):
            return 1
        if re.search(r"^\s*acl_smtp_expn\s*=\s*accept\b", text, flags=re.M):
            return 1
        return 0

    return 2


def U_49(server: Server, *, verbose: bool = True) -> int:
    if not _dns_running(server):
        return 0
    if verbose:
        print("[U-49] DNS 최신 보안 패치는 수동 확인 필요")
        if _command_exists(server, "named"):
            print(_cmd(server, "named -v 2>/dev/null || named -V 2>/dev/null || true"))
    return 2


def U_50(server: Server, *, verbose: bool = True) -> int:
    if not _dns_running(server):
        return 0
    merged = _read_first(server, ["/etc/named.conf", "/etc/bind/named.conf", "/etc/bind/named.conf.options"]) + "\n" + _read_first(
        server, ["/etc/named.boot", "/etc/bind/named.boot"]
    )
    if not merged.strip():
        return 2
    blocks = re.findall(r"allow-transfer\s*\{([^}]*)\}\s*;", merged, flags=re.S | re.I)
    if blocks:
        for b in blocks:
            if "any" in re.sub(r"\s+", " ", b).strip().lower():
                return 1
        return 0
    m = re.search(r"\bxfrnets\b\s+([^\n\r]+)", merged, flags=re.I)
    if m:
        v = m.group(1).strip().lower()
        return 0 if v and "any" not in v else 1
    return 1


def U_51(server: Server, *, verbose: bool = True) -> int:
    if not _dns_running(server):
        return 0
    text = _read_first(server, ["/etc/named.conf", "/etc/bind/named.conf", "/etc/bind/named.conf.options"])
    if not text.strip():
        return 2
    blocks = re.findall(r"allow-update\s*\{([^}]*)\}\s*;", text, flags=re.S | re.I)
    if not blocks:
        return 0
    for b in blocks:
        if "any" in re.sub(r"\s+", " ", b).strip().lower():
            return 1
    return 0


def U_52(server: Server, *, verbose: bool = True) -> int:
    if _inetd_enabled(server, ["telnet"]):
        return 1
    if _xinetd_service_enabled(server, "telnet") is True:
        return 1
    return 1 if _is_port_listening(server, 23) else 0


def U_53(server: Server, *, verbose: bool = True) -> int:
    if not _ftp_running(server):
        return 0
    vs_cfg = _read_first(server, ["/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf"])
    if vs_cfg:
        banner = _config_value(vs_cfg, "ftpd_banner") or ""
        if not banner or re.search(r"vsftpd|\d+\.\d+", banner, flags=re.I):
            return 1
        return 0
    pro_cfg = _read_first(server, ["/etc/proftpd.conf", "/etc/proftpd/proftpd.conf"])
    if pro_cfg:
        m = re.search(r"^\s*ServerIdent\s+(.+)$", pro_cfg, flags=re.M)
        if not m:
            return 1
        v = m.group(1).strip().lower()
        if v.startswith("off"):
            return 0
        return 1 if ("proftpd" in v or re.search(r"\d+\.\d+", v)) else 0
    return 2


def U_54(server: Server, *, verbose: bool = True) -> int:
    if _ftp_running(server):
        return 1
    if _inetd_enabled(server, ["ftp"]):
        return 1
    if _xinetd_service_enabled(server, "ftp") is True:
        return 1
    return 0


def U_55(server: Server, *, verbose: bool = True) -> int:
    for user, _uid, _gid, _home, shell in _get_passwd_entries(server):
        if user != "ftp":
            continue
        return 0 if shell.strip() in {"/bin/false", "/usr/bin/false", "/sbin/nologin", "/usr/sbin/nologin"} else 1
    return 0


def U_56(server: Server, *, verbose: bool = True) -> int:
    if not _ftp_running(server):
        return 0
    vs_cfg = _read_first(server, ["/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf"])
    if vs_cfg:
        enable = (_config_value(vs_cfg, "userlist_enable") or "").lower()
        if enable in {"yes", "true", "1"}:
            return 0
        tw = (_config_value(vs_cfg, "tcp_wrappers") or "").lower()
        if tw in {"yes", "true", "1"}:
            return 0
        return 2
    pro_cfg = _read_first(server, ["/etc/proftpd.conf", "/etc/proftpd/proftpd.conf"])
    if pro_cfg:
        if re.search(r"<Limit\s+LOGIN>", pro_cfg, flags=re.I):
            return 0
        if re.search(r"\bAllowUser\b|\bDenyUser\b|\bAllow\s+from\b|\bDeny\s+from\b", pro_cfg, flags=re.I):
            return 0
        return 2
    return 2


def U_57(server: Server, *, verbose: bool = True) -> int:
    if not _ftp_running(server):
        return 0

    vs_cfg_path = next((p for p in ("/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf") if _exists(server, p)), None)
    if vs_cfg_path:
        cfg = _read(server, vs_cfg_path)
        userlist_enable = (_config_value(cfg, "userlist_enable") or "no").lower()
        userlist_deny = (_config_value(cfg, "userlist_deny") or "yes").lower()
        userlist_file = (_config_value(cfg, "userlist_file") or "").strip()
        if not userlist_file:
            for p in ("/etc/vsftpd.user_list", "/etc/vsftpd/user_list"):
                if _exists(server, p):
                    userlist_file = p
                    break
        if userlist_enable in {"yes", "true", "1"} and userlist_file and _exists(server, userlist_file):
            users = {ln.strip() for ln in _iter_active_lines(_read(server, userlist_file))}
            if userlist_deny in {"yes", "true", "1"}:
                return 0 if "root" in users else 1
            return 0 if "root" not in users else 1

    for p in ("/etc/ftpusers", "/etc/ftpd/ftpusers", "/etc/vsftpd.ftpusers", "/etc/vsftpd/ftpusers"):
        if not _exists(server, p):
            continue
        users = {ln.strip() for ln in _iter_active_lines(_read(server, p))}
        return 0 if "root" in users else 1

    return 2


def U_58(server: Server, *, verbose: bool = True) -> int:
    return 2 if _snmp_running(server) else 0


def U_59(server: Server, *, verbose: bool = True) -> int:
    if not _snmp_running(server):
        return 0
    cfg = _snmp_conf(server)
    if not cfg:
        return 2
    if re.search(r"^\s*(rocommunity|rwcommunity|read-community|write-community)\b", cfg, flags=re.M | re.I):
        return 1
    if re.search(r"^\s*(createUser|rouser|rwuser)\b", cfg, flags=re.M | re.I):
        return 0
    return 2


def U_60(server: Server, *, verbose: bool = True) -> int:
    if not _snmp_running(server):
        return 0
    cfg = _snmp_conf(server)
    if not cfg:
        return 2
    if re.search(r"^\s*(createUser|rouser|rwuser)\b", cfg, flags=re.M | re.I) and not re.search(
        r"^\s*(rocommunity|rwcommunity|read-community|write-community)\b", cfg, flags=re.M | re.I
    ):
        return 0

    communities: List[str] = []
    for line in _iter_active_lines(cfg):
        m = re.match(r"^(rocommunity|rwcommunity|read-community|write-community)\s+(\S+)", line, flags=re.I)
        if m:
            communities.append(m.group(2))
    if not communities:
        return 2

    for comm in communities:
        c = comm.strip()
        if c in {"public", "private"}:
            return 1
        has_alpha = bool(re.search(r"[A-Za-z]", c))
        has_digit = bool(re.search(r"\d", c))
        has_special = bool(re.search(r"[^A-Za-z0-9]", c))
        if has_special:
            if not (has_alpha and has_digit and len(c) >= 8):
                return 1
        else:
            if not (has_alpha and has_digit and len(c) >= 10):
                return 1
    return 0


def U_61(server: Server, *, verbose: bool = True) -> int:
    if not _snmp_running(server):
        return 0
    cfg = _snmp_conf(server)
    if not cfg:
        return 2

    for line in _iter_active_lines(cfg):
        m = re.match(r"^(rocommunity|rwcommunity)\s+(\S+)(?:\s+(\S+))?", line, flags=re.I)
        if m:
            source = (m.group(3) or "").strip().lower()
            if not source or source in {"default", "0.0.0.0/0", "0.0.0.0", "::/0"}:
                return 1
            return 0

        m2 = re.match(r"^com2sec\s+\S+\s+(\S+)\s+\S+", line, flags=re.I)
        if m2:
            source = m2.group(1).strip().lower()
            if source in {"default", "0.0.0.0/0", "0.0.0.0", "::/0"}:
                return 1
            return 0

    if re.search(r"^\s*(createUser|rouser|rwuser)\b", cfg, flags=re.M | re.I):
        return 2
    return 2


def U_62(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[U-62] 로그인 경고 메시지 문구/서비스별 적용은 수동 확인 필요")
        for p in ("/etc/motd", "/etc/issue", "/etc/issue.net"):
            if _exists(server, p):
                print(f"\n== {p} ==")
                print("\n".join(_read(server, p).splitlines()[:20]))
        if _exists(server, "/etc/ssh/sshd_config"):
            cfg = _read(server, "/etc/ssh/sshd_config")
            banner = _config_value(cfg, "Banner")
            if banner:
                print(f"\n== sshd Banner ==\nBanner {banner}")
                if _exists(server, banner):
                    print("\n".join(_read(server, banner).splitlines()[:20]))
    return 2


def U_63(server: Server, *, verbose: bool = True) -> int:
    path = "/etc/sudoers"
    if not _exists(server, path):
        return 0
    res = _check_file_owner_mode(server, path, owners=["root"], max_mode=0o640, verbose=verbose, label="U-63")
    return 2 if res is None else res


def U_64(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[U-64] 패치 정책/최신 여부는 수동 확인 필요")
        print(_cmd(server, "uname -a 2>/dev/null || true"))
        if _command_exists(server, "rpm"):
            print(_cmd(server, "rpm -qa --last 2>/dev/null | head -n 10"))
        if _command_exists(server, "dpkg"):
            print(_cmd(server, "ls -lt /var/log/apt/history.log 2>/dev/null | head -n 3"))
    return 2


def U_65(server: Server, *, verbose: bool = True) -> int:
    if _command_exists(server, "ntpq"):
        out = _cmd(server, "ntpq -pn 2>/dev/null || true")
        return 0 if any(line.lstrip().startswith("*") for line in out.splitlines()) else 1
    if _command_exists(server, "chronyc"):
        out = _cmd(server, "chronyc sources -v 2>/dev/null || true")
        return 0 if any(line.startswith("^*") for line in out.splitlines()) else 1
    if _command_exists(server, "timedatectl"):
        synced = _cmd(server, "timedatectl show -p NTPSynchronized --value 2>/dev/null || true").strip().lower()
        return 0 if synced in {"yes", "true", "1"} else 1
    return 2


def U_66(server: Server, *, verbose: bool = True) -> int:
    if verbose:
        print("[U-66] 로깅 정책/대상은 수동 확인 필요")
        print(_cmd(server, "ps -ef | egrep 'rsyslogd|syslog-ng|journald' | grep -v egrep || true"))
    return 2


def U_67(server: Server, *, verbose: bool = True) -> int:
    target = next((d for d in ("/var/log", "/var/adm", "/var/adm/syslog") if _exists(server, d)), None)
    if not target:
        return 2
    first = _cmd(
        server,
        f"find {_q(target)} -xdev -type f \\( ! -user root -o -perm -0100 -o -perm -0020 -o -perm -0010 -o -perm -0002 -o -perm -0001 \\) -print -quit 2>/dev/null || true",
    ).strip()
    return 0 if not first else 1


CHECKS: Dict[str, Callable[..., int]] = {}
for _i in range(1, 68):
    _code = f"U-{_i:02d}"
    _fn = globals().get(f"U_{_i:02d}")
    if callable(_fn):
        CHECKS[_code] = _fn  # type: ignore[assignment]
