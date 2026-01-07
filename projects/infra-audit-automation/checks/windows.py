from __future__ import annotations

import base64
import json
import re
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

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


_DEFAULT_ADMIN_NAMES = {"administrator", "관리자"}
_DEFAULT_GUEST_NAMES = {"guest", "게스트"}
_ADMIN_SID = "S-1-5-32-544"

_SECPOL_CACHE: Dict[int, str] = {}
_SECPOL_KV_CACHE: Dict[int, Dict[str, str]] = {}


def _ps(server: Server, script: str) -> str:
    """
    Windows(OpenSSH) 환경에서 PowerShell 스크립트를 실행합니다.

    - 인자/따옴표 문제를 피하기 위해 EncodedCommand(UTF-16LE base64)를 사용합니다.
    - 출력은 UTF-8로 고정합니다.
    """

    prelude = (
        "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::UTF8;"
        "$ProgressPreference='SilentlyContinue';"
        "$ErrorActionPreference='Stop';"
    )
    payload = (prelude + script).encode("utf-16le")
    b64 = base64.b64encode(payload).decode("ascii")
    cmd = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {b64}"
    return server.ssh_str(cmd)


def _extract_json(text: str) -> str:
    s = (text or "").strip()
    if not s:
        return ""
    starts = [i for i in (s.find("{"), s.find("[")) if i != -1]
    if not starts:
        return ""
    start = min(starts)
    return s[start:]


def _ps_json(server: Server, script: str) -> Optional[object]:
    out = _ps(server, script)
    payload = _extract_json(out)
    if not payload:
        return None
    return json.loads(payload)


def _get_user_by_rid(server: Server, rid: int) -> Optional[dict]:
    data = _ps_json(
        server,
        (
            "$users = Get-WmiObject Win32_UserAccount | Where-Object { $_.SID -match '-"
            + str(int(rid))
            + "$' };"
            "if (-not $users) { return };"
            "$local = $users | Where-Object { $_.LocalAccount -eq $true } | Select-Object -First 1 Name,SID,Disabled,LocalAccount;"
            "if (-not $local) { $local = $users | Select-Object -First 1 Name,SID,Disabled,LocalAccount };"
            "$local | ConvertTo-Json -Compress"
        ),
    )
    if isinstance(data, dict):
        return data
    if isinstance(data, list) and data:
        if isinstance(data[0], dict):
            return data[0]
    return None


def _secpol_text(server: Server) -> str:
    key = id(server)
    cached = _SECPOL_CACHE.get(key)
    if cached is not None:
        return cached
    text = _ps(
        server,
        (
            "$path = Join-Path $env:TEMP 'codex_secpol.cfg';"
            "secedit /export /cfg $path | Out-Null;"
            "$txt = Get-Content -LiteralPath $path -Raw;"
            "Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue | Out-Null;"
            "$txt"
        ),
    )
    _SECPOL_CACHE[key] = text
    return text


def _secpol_kv(text: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith(";") or line.startswith("#") or line.startswith("["):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k.strip()] = v.strip()
    return data


def _secpol_values(server: Server) -> Dict[str, str]:
    key = id(server)
    cached = _SECPOL_KV_CACHE.get(key)
    if cached is not None:
        return cached
    values = _secpol_kv(_secpol_text(server))
    _SECPOL_KV_CACHE[key] = values
    return values


def _int(v: Optional[str]) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(str(v).strip())
    except Exception:
        return None


def _parse_sid_list(raw: str) -> List[str]:
    # secedit export는 `*S-1-...` 형태를 콤마로 나열합니다.
    items: List[str] = []
    for tok in (raw or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        if tok.startswith("*"):
            tok = tok[1:].strip()
        if tok:
            items.append(tok)
    return items


def _resolve_sids(server: Server, sids: Sequence[str]) -> List[str]:
    if not sids:
        return []

    quoted = ",".join(json.dumps(str(s)) for s in sids)
    script = "\n".join(
        [
            f"$sids = @({quoted})",
            "if (-not $sids) { return }",
            "$out = @()",
            "foreach ($s in $sids) {",
            "  try {",
            "    $sid = New-Object System.Security.Principal.SecurityIdentifier($s)",
            "    $out += $sid.Translate([System.Security.Principal.NTAccount]).Value",
            "  } catch {",
            "    $out += $s",
            "  }",
            "}",
            "$out | ConvertTo-Json -Compress",
        ]
    )
    data = _ps_json(server, script)
    if isinstance(data, list):
        return [str(x) for x in data]
    if isinstance(data, str):
        return [data]
    return [str(x) for x in sids]


def _reg_get(server: Server, ps_path: str, name: str) -> Optional[object]:
    path_s = ps_path.replace("'", "''")
    name_s = name.replace("'", "''")
    script = "\n".join(
        [
            f"$p='{path_s}'",
            f"$n='{name_s}'",
            "try {",
            "  $v = (Get-ItemProperty -Path $p -Name $n -ErrorAction Stop).$n",
            "  $v | ConvertTo-Json -Compress",
            "} catch { }",
        ]
    )
    return _ps_json(server, script)


def _reg_get_many(server: Server, ps_path: str, names: Sequence[str]) -> Optional[dict]:
    path_s = ps_path.replace("'", "''")
    props = ",".join(json.dumps(str(n)) for n in names)
    script = "\n".join(
        [
            f"$p='{path_s}'",
            f"$names = @({props})",
            "try {",
            "  $o = Get-ItemProperty -Path $p -ErrorAction Stop",
            "  $out = [ordered]@{}",
            "  foreach ($n in $names) { $out[$n] = $o.$n }",
            "  [pscustomobject]$out | ConvertTo-Json -Compress",
            "} catch { }",
        ]
    )
    data = _ps_json(server, script)
    return data if isinstance(data, dict) else None


def _truthy(value: object) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "enabled"}:
        return True
    if text in {"0", "false", "no", "disabled"}:
        return False
    return None


def W_01(server: Server, *, verbose: bool = True) -> int:
    """
    W-01 Administrator 계정 이름 변경 등 보안성 강화
    - 양호: Administrator 기본 계정 이름을 변경한 경우(또는 강화된 비밀번호 적용)
    - 취약: Administrator 기본 계정 이름을 변경하지 않은 경우(또는 단순 비밀번호 적용)

    자동판정은 "계정 이름 변경" 여부만 확인합니다.
    """

    user = _get_user_by_rid(server, 500)
    if not user:
        if verbose:
            print("[W-01] RID-500 계정을 찾지 못했습니다(수동 확인 필요).")
        return 2

    name = str(user.get("Name") or "").strip()
    sid = str(user.get("SID") or "").strip()
    if verbose:
        print(f"[W-01] RID-500 name={name!r}, sid={sid!r}")

    if name.lower() in _DEFAULT_ADMIN_NAMES:
        if verbose:
            print("[W-01] Administrator 기본 계정명이 그대로입니다(이름 변경 권고).")
            print("[W-01] 비밀번호 복잡도 자체는 자동 확인하지 않습니다.")
        return 1
    return 0


def W_02(server: Server, *, verbose: bool = True) -> int:
    """
    W-02 Guest 계정 비활성화
    - 양호: Guest 계정 Disabled=True
    - 취약: Guest 계정 Disabled=False
    """

    user = _get_user_by_rid(server, 501)
    if not user:
        if verbose:
            print("[W-02] RID-501(GUEST) 계정을 찾지 못했습니다(수동 확인 필요).")
        return 2

    name = str(user.get("Name") or "").strip()
    disabled = user.get("Disabled")
    if verbose:
        print(f"[W-02] RID-501 name={name!r}, Disabled={disabled!r}")

    # 일부 환경에서 Disabled 값이 문자열로 내려오는 경우를 고려
    disabled_bool = str(disabled).strip().lower() in {"true", "1"} if not isinstance(disabled, bool) else disabled

    if name.lower() in _DEFAULT_GUEST_NAMES and disabled_bool:
        return 0
    if disabled_bool:
        # 이름이 변경된 Guest일 수 있으나 Disabled면 목적(비활성화)을 만족
        return 0
    return 1


def W_04(server: Server, *, verbose: bool = True) -> int:
    """
    W-04 계정 잠금 임계값 설정
    - 양호: LockoutBadCount 1~5
    - 취약: 미설정(0) 또는 5 초과
    """

    kv = _secpol_values(server)
    raw = kv.get("LockoutBadCount")
    val = _int(raw)
    if verbose:
        print(f"[W-04] LockoutBadCount={raw!r}")
    if val is None:
        return 2
    if val == 0:
        return 1
    return 0 if val <= 5 else 1


def W_05(server: Server, *, verbose: bool = True) -> int:
    """
    W-05 해독 가능한 암호화를 사용하여 암호 저장 해제
    - 양호: ClearTextPassword=0
    - 취약: ClearTextPassword=1
    """

    kv = _secpol_values(server)
    raw = kv.get("ClearTextPassword")
    val = _int(raw)
    if verbose:
        print(f"[W-05] ClearTextPassword={raw!r}")
    if val is None:
        return 2
    return 0 if val == 0 else 1


def W_08(server: Server, *, verbose: bool = True) -> int:
    """
    W-08 계정 잠금 기간 설정
    - 양호: LockoutDuration >= 60 AND ResetLockoutCount >= 60
    - 취약: 미설정/60 미만
    """

    kv = _secpol_values(server)
    raw_duration = kv.get("LockoutDuration")
    raw_reset = kv.get("ResetLockoutCount")
    duration = _int(raw_duration)
    reset = _int(raw_reset)
    if verbose:
        print(f"[W-08] LockoutDuration={raw_duration!r}, ResetLockoutCount={raw_reset!r}")
    if duration is None or reset is None:
        return 2
    return 0 if duration >= 60 and reset >= 60 else 1


def W_09(server: Server, *, verbose: bool = True) -> int:
    """
    W-09 비밀번호 관리 정책 설정

    기준(가이드):
    - 복잡성 사용(PasswordComplexity=1)
    - 최근 암호 기억 >= 4(PasswordHistorySize)
    - 최대 암호 사용 기간 90일 이하(0=무기한은 취약으로 처리)
    - 최소 암호 길이 >= 8
    - 최소 암호 사용 기간 >= 1
    """

    kv = _secpol_values(server)
    raw_complex = kv.get("PasswordComplexity")
    raw_history = kv.get("PasswordHistorySize")
    raw_max_age = kv.get("MaximumPasswordAge")
    raw_min_len = kv.get("MinimumPasswordLength")
    raw_min_age = kv.get("MinimumPasswordAge")

    complex_v = _int(raw_complex)
    history_v = _int(raw_history)
    max_age_v = _int(raw_max_age)
    min_len_v = _int(raw_min_len)
    min_age_v = _int(raw_min_age)

    if verbose:
        print(
            "[W-09] "
            + ", ".join(
                [
                    f"PasswordComplexity={raw_complex!r}",
                    f"PasswordHistorySize={raw_history!r}",
                    f"MaximumPasswordAge={raw_max_age!r}",
                    f"MinimumPasswordLength={raw_min_len!r}",
                    f"MinimumPasswordAge={raw_min_age!r}",
                ]
            )
        )

    if None in (complex_v, history_v, max_age_v, min_len_v, min_age_v):
        return 2

    ok = True
    ok &= complex_v == 1
    ok &= history_v >= 4
    ok &= 1 <= max_age_v <= 90
    ok &= min_len_v >= 8
    ok &= min_age_v >= 1

    return 0 if ok else 1


def W_07(server: Server, *, verbose: bool = True) -> int:
    """
    W-07 Everyone 사용 권한을 익명 사용자에게 적용
    - 양호: EveryoneIncludesAnonymous=0(사용 안 함)
    - 취약: EveryoneIncludesAnonymous=1(사용)
    """

    kv = _secpol_values(server)
    raw = kv.get("EveryoneIncludesAnonymous")
    val = _int(raw)
    if val is None:
        reg = _reg_get(server, "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "EveryoneIncludesAnonymous")
        val = _int(str(reg)) if reg is not None else None
    if verbose:
        print(f"[W-07] EveryoneIncludesAnonymous={raw!r}" if raw is not None else "[W-07] EveryoneIncludesAnonymous not found in secedit")
        if val is not None and raw is None:
            print(f"[W-07] registry EveryoneIncludesAnonymous={val}")
    if val is None:
        return 2
    return 0 if val == 0 else 1


def W_10(server: Server, *, verbose: bool = True) -> int:
    """
    W-10 마지막 사용자 이름 표시 안 함
    - 양호: DontDisplayLastUserName=1(사용)
    - 취약: DontDisplayLastUserName=0(사용 안 함)
    """

    kv = _secpol_values(server)
    raw = kv.get("DontDisplayLastUserName")
    val = _int(raw)
    if verbose:
        print(f"[W-10] DontDisplayLastUserName={raw!r}")
    if val is None:
        return 2
    return 0 if val == 1 else 1


def W_11(server: Server, *, verbose: bool = True) -> int:
    """
    W-11 로컬 로그온 허용
    - 양호: SeInteractiveLogonRight에 Administrators, IUSR_만 존재
    - 취약: 그 외 계정/그룹 존재
    """

    kv = _secpol_values(server)
    raw = kv.get("SeInteractiveLogonRight")
    if not raw:
        if verbose:
            print("[W-11] SeInteractiveLogonRight not found")
        return 2

    sids = _parse_sid_list(raw)
    names = _resolve_sids(server, sids)
    if verbose:
        for sid, name in zip(sids, names):
            print(f"[W-11] assignee sid={sid} name={name}")

    unauthorized: List[Tuple[str, str]] = []
    for sid, name in zip(sids, names):
        if sid == _ADMIN_SID:
            continue
        leaf = name.split("\\\\")[-1].upper()
        if leaf.startswith("IUSR"):
            continue
        unauthorized.append((sid, name))

    if unauthorized and verbose:
        print("[W-11] 허용되지 않은 계정/그룹:")
        for sid, name in unauthorized:
            print(f"  - {name} ({sid})")

    return 0 if not unauthorized else 1


def W_12(server: Server, *, verbose: bool = True) -> int:
    """
    W-12 익명 SID/이름 변환 허용 해제
    - 양호: LSAAnonymousNameLookup=0(사용 안 함)
    - 취약: LSAAnonymousNameLookup=1(사용)
    """

    kv = _secpol_values(server)
    raw = kv.get("LSAAnonymousNameLookup")
    val = _int(raw)
    if verbose:
        print(f"[W-12] LSAAnonymousNameLookup={raw!r}")
    if val is None:
        return 2
    return 0 if val == 0 else 1


def W_13(server: Server, *, verbose: bool = True) -> int:
    """
    W-13 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한
    - 양호: LimitBlankPasswordUse=1(사용)
    - 취약: LimitBlankPasswordUse=0(사용 안 함)
    """

    kv = _secpol_values(server)
    raw = kv.get("LimitBlankPasswordUse")
    val = _int(raw)
    if verbose:
        print(f"[W-13] LimitBlankPasswordUse={raw!r}")
    if val is None:
        return 2
    return 0 if val == 1 else 1


def W_17(server: Server, *, verbose: bool = True) -> int:
    """
    W-17 하드디스크 기본 공유 제거
    - 양호: AutoShareServer(또는 AutoShareWks)=0 이고 기본 공유(ADMIN$, C$...)가 없는 경우
    - 취약: AutoShare*=1 이거나 기본 공유가 존재하는 경우
    """

    reg_path = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
    reg = _reg_get_many(server, reg_path, ["AutoShareServer", "AutoShareWks"])
    auto_share = None
    if reg:
        if reg.get("AutoShareServer") is not None:
            auto_share = _int(str(reg.get("AutoShareServer")))
        elif reg.get("AutoShareWks") is not None:
            auto_share = _int(str(reg.get("AutoShareWks")))

    shares = _ps_json(
        server,
        (
            "try {"
            "  Get-SmbShare | Select-Object Name | ConvertTo-Json -Compress"
            "} catch {"
            "  $out = @();"
            "  try {"
            "    $txt = (net share) -join \"`n\";"
            "    $out = $txt"
            "  } catch { }"
            "  $out | ConvertTo-Json -Compress"
            "}"
        ),
    )

    share_names: List[str] = []
    if isinstance(shares, list):
        for s in shares:
            if isinstance(s, dict):
                name = str(s.get("Name") or "").strip()
                if name:
                    share_names.append(name)
            else:
                name = str(s).strip()
                if name:
                    share_names.append(name)
    elif isinstance(shares, dict):
        name = str(shares.get("Name") or "").strip()
        if name:
            share_names.append(name)
    elif isinstance(shares, str):
        # net share 출력 파싱(최소): 첫 열(공유명) 추출
        for line in shares.splitlines():
            if not line.strip() or line.strip().startswith("Share name") or line.strip().startswith("---"):
                continue
            parts = line.split()
            if parts:
                share_names.append(parts[0].strip())

    default_shares = []
    for name in share_names:
        upper = name.upper()
        if upper in {"ADMIN$"} or re.fullmatch(r"[A-Z]\\$", upper):
            default_shares.append(name)

    if verbose:
        print(f"[W-17] AutoShare(Registry)={auto_share!r} (0 권고)")
        if default_shares:
            print("[W-17] 기본 공유 감지:", ", ".join(sorted(default_shares)))

    if auto_share is None:
        return 2
    if auto_share != 0 or default_shares:
        return 1
    return 0


def _rdp_enabled(server: Server) -> Optional[bool]:
    reg = _reg_get(server, "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "fDenyTSConnections")
    val = _int(str(reg)) if reg is not None else None
    if val is None:
        return None
    return val == 0


def W_28(server: Server, *, verbose: bool = True) -> int:
    """
    W-28 터미널 서비스 암호화 수준 설정
    - 양호: RDP 미사용 또는 암호화 수준 >= ClientCompatible(중간)
    - 취약: RDP 사용 + 암호화 수준이 Low
    """

    enabled = _rdp_enabled(server)
    if enabled is False:
        if verbose:
            print("[W-28] RDP 비활성화 상태")
        return 0
    if enabled is None:
        if verbose:
            print("[W-28] RDP 활성 여부 확인 실패")
        return 2

    policy_path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
    local_path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
    policy_val = _reg_get(server, policy_path, "MinEncryptionLevel")
    local_val = _reg_get(server, local_path, "MinEncryptionLevel")
    val = _int(str(policy_val)) if policy_val is not None else _int(str(local_val)) if local_val is not None else None

    if verbose:
        print(f"[W-28] MinEncryptionLevel policy={policy_val!r}, local={local_val!r} -> effective={val!r}")

    if val is None:
        return 2
    return 0 if val >= 2 else 1


def W_34(server: Server, *, verbose: bool = True) -> int:
    """
    W-34 Telnet 서비스 비활성화
    - 양호: Telnet 서비스 미구동 또는 인증 방법이 NTLM
    - 취약: Telnet 서비스 구동 + 인증 방법이 NTLM 아님
    """

    svc = _ps_json(
        server,
        "try { Get-Service -Name 'TlntSvr' -ErrorAction Stop | Select-Object Status | ConvertTo-Json -Compress } catch { }",
    )
    status = None
    if isinstance(svc, dict):
        status = str(svc.get("Status") or "").strip()
    elif isinstance(svc, str):
        status = svc.strip()

    if not status:
        if verbose:
            print("[W-34] Telnet 서비스가 설치되어 있지 않습니다.")
        return 0
    if status.lower() != "running":
        if verbose:
            print(f"[W-34] Telnet 서비스 상태: {status}")
        return 0

    out = _ps(
        server,
        "try { tlntadmn config 2>$null } catch { '' }",
    )
    if verbose:
        print("[W-34] tlntadmn config output:")
        print(out.strip())
    if not out.strip():
        return 2
    return 0 if "NTLM" in out.upper() else 1


def W_36(server: Server, *, verbose: bool = True) -> int:
    """
    W-36 원격터미널 접속 타임아웃 설정
    - 양호: RDP 미사용 또는 MaxIdleTime <= 30분
    - 취약: 미설정 또는 30분 초과
    """

    enabled = _rdp_enabled(server)
    if enabled is False:
        if verbose:
            print("[W-36] RDP 비활성화 상태")
        return 0
    if enabled is None:
        if verbose:
            print("[W-36] RDP 활성 여부 확인 실패")
        return 2

    policy_path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
    raw = _reg_get(server, policy_path, "MaxIdleTime")
    ms = _int(str(raw)) if raw is not None else None
    if verbose:
        print(f"[W-36] MaxIdleTime(ms)={raw!r}")
    if ms is None or ms <= 0:
        return 1
    return 0 if ms <= 30 * 60 * 1000 else 1


def W_48(server: Server, *, verbose: bool = True) -> int:
    """
    W-48 로그온하지 않고 시스템 종료 허용
    - 양호: ShutdownWithoutLogon=0(사용 안 함)
    - 취약: ShutdownWithoutLogon=1(사용)
    """

    kv = _secpol_values(server)
    raw = kv.get("ShutdownWithoutLogon")
    val = _int(raw)
    if verbose:
        print(f"[W-48] ShutdownWithoutLogon={raw!r}")
    if val is None:
        return 2
    return 0 if val == 0 else 1


def W_49(server: Server, *, verbose: bool = True) -> int:
    """
    W-49 원격 시스템에서 강제로 시스템 종료
    - 양호: SeRemoteShutdownPrivilege에 Administrators만 존재
    - 취약: 그 외 계정/그룹 존재
    """

    kv = _secpol_values(server)
    raw = kv.get("SeRemoteShutdownPrivilege")
    if not raw:
        if verbose:
            print("[W-49] SeRemoteShutdownPrivilege not found")
        return 2
    sids = set(_parse_sid_list(raw))
    if verbose:
        print(f"[W-49] SeRemoteShutdownPrivilege={sorted(sids)}")
    return 0 if sids == {_ADMIN_SID} else 1


def W_50(server: Server, *, verbose: bool = True) -> int:
    """
    W-50 보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료
    - 양호: CrashOnAuditFail=0(사용 안 함)
    - 취약: CrashOnAuditFail=1(사용)
    """

    kv = _secpol_values(server)
    raw = kv.get("CrashOnAuditFail")
    val = _int(raw)
    if verbose:
        print(f"[W-50] CrashOnAuditFail={raw!r}")
    if val is None:
        return 2
    return 0 if val == 0 else 1


def W_51(server: Server, *, verbose: bool = True) -> int:
    """
    W-51 SAM 계정과 공유의 익명 열거 허용 안 함
    - 양호: RestrictAnonymous >= 1 (사용)
    - 취약: RestrictAnonymous == 0 (사용 안 함)
    """

    kv = _secpol_values(server)
    raw = kv.get("RestrictAnonymous")
    val = _int(raw)
    if val is None:
        reg = _reg_get(server, "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "RestrictAnonymous")
        val = _int(str(reg)) if reg is not None else None
    if verbose:
        print(f"[W-51] RestrictAnonymous={raw!r}" if raw is not None else "[W-51] RestrictAnonymous not found in secedit")
        if val is not None and raw is None:
            print(f"[W-51] registry RestrictAnonymous={val}")
    if val is None:
        return 2
    return 0 if val >= 1 else 1


def W_52(server: Server, *, verbose: bool = True) -> int:
    """
    W-52 Autologon 기능 제어
    - 양호: AutoAdminLogon 값이 없거나 0
    - 취약: AutoAdminLogon 값이 1
    """

    path = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    raw = _reg_get(server, path, "AutoAdminLogon")
    text = str(raw).strip() if raw is not None else ""
    if verbose:
        print(f"[W-52] AutoAdminLogon={raw!r}")
    if not text:
        return 0
    return 1 if text == "1" else 0


def W_53(server: Server, *, verbose: bool = True) -> int:
    """
    W-53 이동식 미디어 포맷 및 꺼내기 허용
    - 양호: AllocateDASD=0 (Administrators)
    - 취약: 그 외
    """

    kv = _secpol_values(server)
    raw = kv.get("AllocateDASD")
    val = _int(raw)
    if verbose:
        print(f"[W-53] AllocateDASD={raw!r}")
    if val is None:
        return 2
    return 0 if val == 0 else 1


def W_54(server: Server, *, verbose: bool = True) -> int:
    """
    W-54 Dos 공격 방어 레지스트리 설정
    - 양호:
      - SynAttackProtect >= 1
      - EnableDeadGWDetect == 0
      - KeepAliveTime == 300000
      - NoNameReleaseOnDemand == 1
    - 취약: 미설정 또는 기준 불만족
    """

    path = "HKLM:\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters"
    reg = _reg_get_many(
        server,
        path,
        ["SynAttackProtect", "EnableDeadGWDetect", "KeepAliveTime", "NoNameReleaseOnDemand"],
    )
    if verbose:
        print(f"[W-54] {reg!r}")
    if not reg:
        return 2

    syn = _int(str(reg.get("SynAttackProtect"))) if reg.get("SynAttackProtect") is not None else None
    deadgw = _int(str(reg.get("EnableDeadGWDetect"))) if reg.get("EnableDeadGWDetect") is not None else None
    keep = _int(str(reg.get("KeepAliveTime"))) if reg.get("KeepAliveTime") is not None else None
    noname = _int(str(reg.get("NoNameReleaseOnDemand"))) if reg.get("NoNameReleaseOnDemand") is not None else None

    ok = syn is not None and syn >= 1
    ok &= deadgw == 0
    ok &= keep == 300000
    ok &= noname == 1
    return 0 if ok else 1


def W_55(server: Server, *, verbose: bool = True) -> int:
    """
    W-55 사용자가 프린터 드라이버를 설치할 수 없게 함
    - 양호: AddPrinterDrivers=1 (사용)
    - 취약: AddPrinterDrivers=0 (사용 안 함)
    """

    kv = _secpol_values(server)
    raw = kv.get("AddPrinterDrivers")
    val = _int(raw)
    if verbose:
        print(f"[W-55] AddPrinterDrivers={raw!r}")
    if val is None:
        return 2
    return 0 if val == 1 else 1


def W_56(server: Server, *, verbose: bool = True) -> int:
    """
    W-56 SMB 세션 중단 관리 설정
    - 양호:
      - EnableForcedLogOff=True(사용)
      - AutoDisconnectTimeout <= 15(분)
    - 취약: 그 외
    """

    data = _ps_json(
        server,
        (
            "try {"
            "  $cfg = Get-SmbServerConfiguration -ErrorAction Stop;"
            "  [pscustomobject]@{"
            "    EnableForcedLogOff=$cfg.EnableForcedLogOff;"
            "    AutoDisconnectTimeout=$cfg.AutoDisconnectTimeout"
            "  } | ConvertTo-Json -Compress"
            "} catch {"
            "  $p='HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LanmanServer\\\\Parameters';"
            "  try {"
            "    $o = Get-ItemProperty -Path $p -ErrorAction Stop;"
            "    [pscustomobject]@{"
            "      EnableForcedLogOff=$o.EnableForcedLogOff;"
            "      AutoDisconnectTimeout=$o.AutoDisconnect"
            "    } | ConvertTo-Json -Compress"
            "  } catch { }"
            "}"
        ),
    )
    if verbose:
        print(f"[W-56] {data!r}")
    if not isinstance(data, dict):
        return 2

    forced = _truthy(data.get("EnableForcedLogOff"))
    idle = data.get("AutoDisconnectTimeout")
    idle_v = _int(str(idle)) if idle is not None else None
    if forced is None or idle_v is None:
        return 2

    return 0 if forced and idle_v <= 15 else 1


def W_57(server: Server, *, verbose: bool = True) -> int:
    """
    W-57 로그온 시 경고 메시지 설정
    - 양호: LegalNoticeCaption/LegalNoticeText 모두 설정
    - 취약: 제목/내용이 비어있음
    """

    path = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    reg = _reg_get_many(server, path, ["LegalNoticeCaption", "LegalNoticeText"])
    if verbose:
        print(f"[W-57] {reg!r}")
    if not reg:
        return 2
    cap = str(reg.get("LegalNoticeCaption") or "").strip()
    txt = str(reg.get("LegalNoticeText") or "").strip()
    return 0 if cap and txt else 1


def W_59(server: Server, *, verbose: bool = True) -> int:
    """
    W-59 LAN Manager 인증 수준
    - 양호: LmCompatibilityLevel >= 3 (NTLMv2 응답만 보냄 이상)
    - 취약: 0~2 (LM/NTLM 허용)
    """

    kv = _secpol_values(server)
    raw = kv.get("LmCompatibilityLevel")
    val = _int(raw)
    if val is None:
        reg = _reg_get(server, "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "LmCompatibilityLevel")
        val = _int(str(reg)) if reg is not None else None
    if verbose:
        print(f"[W-59] LmCompatibilityLevel={raw!r}" if raw is not None else "[W-59] LmCompatibilityLevel not found in secedit")
        if val is not None and raw is None:
            print(f"[W-59] registry LmCompatibilityLevel={val}")
    if val is None:
        return 2
    return 0 if val >= 3 else 1


def W_60(server: Server, *, verbose: bool = True) -> int:
    """
    W-60 보안 채널 데이터 디지털 암호화 또는 서명
    - 양호: RequireSignOrSeal=1, SealSecureChannel=1, SignSecureChannel=1
    - 취약: 일부라도 사용 안 함
    """

    kv = _secpol_values(server)
    raw_require = kv.get("RequireSignOrSeal")
    raw_seal = kv.get("SealSecureChannel")
    raw_sign = kv.get("SignSecureChannel")

    require_v = _int(raw_require)
    seal_v = _int(raw_seal)
    sign_v = _int(raw_sign)

    if None in (require_v, seal_v, sign_v):
        reg = _reg_get_many(
            server,
            "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
            ["RequireSignOrSeal", "SealSecureChannel", "SignSecureChannel"],
        )
        if reg:
            require_v = require_v if require_v is not None else _int(str(reg.get("RequireSignOrSeal")))
            seal_v = seal_v if seal_v is not None else _int(str(reg.get("SealSecureChannel")))
            sign_v = sign_v if sign_v is not None else _int(str(reg.get("SignSecureChannel")))

    if verbose:
        print(
            "[W-60] "
            + ", ".join(
                [
                    f"RequireSignOrSeal={require_v!r}",
                    f"SealSecureChannel={seal_v!r}",
                    f"SignSecureChannel={sign_v!r}",
                ]
            )
        )

    if None in (require_v, seal_v, sign_v):
        return 2

    ok = require_v == 1 and seal_v == 1 and sign_v == 1
    return 0 if ok else 1


def W_03(server: Server, *, verbose: bool = True) -> int:
    """
    W-03 불필요한 계정 제거
    - 양호: 불필요한 계정이 존재하지 않는 경우
    - 취약: 불필요한 계정이 존재하는 경우

    자동으로 “불필요” 여부를 판단하기 어렵기 때문에 계정 목록을 출력하고 2를 반환합니다.
    """

    users = _ps_json(
        server,
        (
            "try {"
            "  Get-WmiObject Win32_UserAccount |"
            "    Where-Object { $_.LocalAccount -eq $true } |"
            "    Select-Object Name,Disabled,SID,Description |"
            "    ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    if verbose:
        print(f"[W-03] local users={users!r}")
    return 2


def W_06(server: Server, *, verbose: bool = True) -> int:
    """
    W-06 관리자 그룹에 최소한의 사용자 포함
    - 양호: Administrators 그룹 구성원을 1명 이하로 유지하거나, 불필요한 관리자 계정이 없는 경우
    - 취약: 불필요한 관리자 계정 존재

    환경별로 상이하여 구성원 목록을 출력하고 2를 반환합니다.
    """

    members = _ps_json(
        server,
        (
            "try {"
            "  Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |"
            "    Select-Object Name,ObjectClass,PrincipalSource |"
            "    ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    if members is None:
        text = _ps(server, "try { (net localgroup administrators) -join \"`n\" } catch { '' }")
        if verbose:
            print("[W-06] net localgroup administrators:")
            print(text.strip())
        return 2
    if verbose:
        print(f"[W-06] Administrators members={members!r}")
    return 2


def W_14(server: Server, *, verbose: bool = True) -> int:
    """
    W-14 원격터미널 접속 가능한 사용자 그룹 제한
    - 양호: 불필요한 계정이 등록되지 않고(관리자 외 별도 원격 계정 운영 등) 제한된 경우
    - 취약: 관리자 외 별도 계정이 없거나 불필요 계정 등록

    조직 정책/운영 방식에 따라 달라질 수 있어 현황 출력 후 2를 반환합니다.
    """

    kv = _secpol_values(server)
    raw = kv.get("SeRemoteInteractiveLogonRight") or ""
    sids = _parse_sid_list(raw)
    names = _resolve_sids(server, sids)

    rdu_members = _ps_json(
        server,
        (
            "try {"
            "  $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-555');"
            "  $name = $sid.Translate([System.Security.Principal.NTAccount]).Value;"
            "  $group = $name.Split('\\\\')[-1];"
            "  Get-LocalGroupMember -Group $group -ErrorAction Stop |"
            "    Select-Object Name,ObjectClass,PrincipalSource |"
            "    ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )

    if verbose:
        print("[W-14] SeRemoteInteractiveLogonRight assignees:")
        for sid, name in zip(sids, names):
            print(f"  - {name} ({sid})")
        print(f"[W-14] Remote Desktop Users members={rdu_members!r}")
    return 2


def W_15(server: Server, *, verbose: bool = True) -> int:
    """
    W-15 사용자 개인키 사용 시 암호 입력
    - 양호: ForceKeyProtection=2 (키를 사용할 때마다 암호 입력)
    - 취약: ForceKeyProtection!=2
    """

    kv = _secpol_values(server)
    raw = kv.get("ForceKeyProtection")
    val = _int(raw)
    if verbose:
        print(f"[W-15] ForceKeyProtection={raw!r}")
    if val is None:
        return 2
    return 0 if val == 2 else 1


def W_16(server: Server, *, verbose: bool = True) -> int:
    """
    W-16 공유 권한 및 사용자 그룹 설정
    - 양호: 일반 공유가 없거나, 공유 접근 권한에 Everyone이 없는 경우
    - 취약: 일반 공유 접근 권한에 Everyone이 있는 경우
    """

    data = _ps_json(
        server,
        (
            "try {"
            "  $shares = Get-SmbShare | Where-Object { $_.Special -eq $false } | Select-Object Name,Path;"
            "  $out = @();"
            "  foreach ($s in $shares) {"
            "    $acc = Get-SmbShareAccess -Name $s.Name | Select-Object AccountName,AccessControlType,AccessRight;"
            "    $out += [pscustomobject]@{Name=$s.Name; Path=$s.Path; Access=$acc};"
            "  }"
            "  $out | ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    if not isinstance(data, list):
        if verbose:
            print(f"[W-16] Get-SmbShare/Get-SmbShareAccess 결과 없음: {data!r}")
        return 2

    bad: List[str] = []
    for share in data:
        if not isinstance(share, dict):
            continue
        name = str(share.get("Name") or "").strip()
        access = share.get("Access")
        rows = access if isinstance(access, list) else [access] if isinstance(access, dict) else []
        for row in rows:
            if not isinstance(row, dict):
                continue
            account = str(row.get("AccountName") or "").strip()
            if account.lower() in {"everyone", "모든 사람"} or account.endswith("\\Everyone") or account.endswith("\\모든 사람"):
                bad.append(f"{name}: {account}")

    if verbose:
        print(f"[W-16] shares={len(data)}, everyone_hits={bad}")
    return 0 if not bad else 1


def W_18(server: Server, *, verbose: bool = True) -> int:
    """
    W-18 불필요한 서비스 제거

    가이드의 “일반적으로 불필요한 서비스”는 환경에 따라 달라질 수 있어,
    대표 서비스 상태를 출력하고 2를 반환합니다.
    """

    service_names = [
        "Alerter",
        "wuauserv",  # Windows Update(Automatic Updates)
        "ClipSrv",  # Clipbook
        "Browser",  # Computer Browser
        "CryptSvc",  # Cryptographic Services
        "Dhcp",  # DHCP Client
        "TrkWks",  # Distributed Link Tracking Client
        "TrkSrv",  # Distributed Link Tracking Server
        "Dnscache",  # DNS Client
        "WerSvc",  # Error Reporting Service(Windows Error Reporting)
        "ERSvc",  # (구버전)
        "HidServ",  # Human Interface Device Access
        "ImapiService",  # IMAPI CD-Burning COM Service
        "Irmon",  # Infrared Monitor(구버전)
        "Messenger",
        "mnmsrvc",  # NetMeeting Remote Desktop Sharing
        "WmdmPmSN",  # Portable Media Serial Number
        "Spooler",  # Print Spooler
        "RemoteRegistry",
        "simptcp",  # Simple TCP/IP Services
    ]

    quoted = ",".join(json.dumps(s) for s in service_names)
    data = _ps_json(
        server,
        (
            f"$names=@({quoted});"
            " $out=@();"
            " foreach ($n in $names) {"
            "  try { $svc = Get-Service -Name $n -ErrorAction Stop;"
            "    $out += [pscustomobject]@{Name=$n; Status=$svc.Status.ToString(); DisplayName=$svc.DisplayName};"
            "  } catch { }"
            " }"
            " $out | ConvertTo-Json -Compress"
        ),
    )
    if verbose:
        print(f"[W-18] services={data!r}")
    return 2


def W_19(server: Server, *, verbose: bool = True) -> int:
    """
    W-19 불필요한 IIS 서비스 구동 점검
    - 양호: IIS 미사용(미설치/미구동) 또는 필요 사용
    - 취약: 불필요 사용

    “필요 여부”는 환경에 따라 달라 서비스 상태를 출력하고,
    IIS가 실행 중이면 2를 반환합니다.
    """

    svc = _ps_json(
        server,
        "try { Get-Service -Name 'W3SVC' -ErrorAction Stop | Select-Object Status | ConvertTo-Json -Compress } catch { }",
    )
    status = str(svc.get("Status") or "").strip() if isinstance(svc, dict) else ""
    if verbose:
        print(f"[W-19] W3SVC status={status!r}")
    if not status:
        return 0
    if status.lower() != "running":
        return 0
    return 2


def W_20(server: Server, *, verbose: bool = True) -> int:
    """
    W-20 NetBIOS 바인딩 서비스 구동 점검
    - 양호: IPEnabled 어댑터에서 TcpipNetbiosOptions=2(Disable)인 경우
    - 취약: 그 외(0=DHCP, 1=Enable 포함)
    """

    data = _ps_json(
        server,
        (
            "try {"
            "  Get-WmiObject Win32_NetworkAdapterConfiguration |"
            "    Where-Object { $_.IPEnabled -eq $true } |"
            "    Select-Object Description,TcpipNetbiosOptions |"
            "    ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    rows = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    if not rows:
        return 2

    bad = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        desc = str(row.get("Description") or "").strip()
        opt = row.get("TcpipNetbiosOptions")
        opt_i = _int(str(opt)) if opt is not None else None
        if verbose:
            print(f"[W-20] {desc}: TcpipNetbiosOptions={opt_i!r}")
        if opt_i != 2:
            bad.append(desc or "(unknown)")

    return 0 if not bad else 1


def W_21(server: Server, *, verbose: bool = True) -> int:
    """
    W-21 암호화되지 않는 FTP 서비스 비활성화
    - 양호: FTP 미사용 또는 Secure FTP 사용
    - 취약: 암호화되지 않는 FTP 사용

    FTPS(SSL/TLS 강제) 설정까지는 자동 판정이 어려워,
    FTP 서비스/포트 상태를 출력하고 2를 반환합니다(FTP가 동작 중인 경우).
    """

    svc = _ps_json(
        server,
        "try { Get-Service -Name 'FTPSVC' -ErrorAction Stop | Select-Object Status | ConvertTo-Json -Compress } catch { }",
    )
    status = str(svc.get("Status") or "").strip() if isinstance(svc, dict) else ""
    listening = _ps_json(
        server,
        (
            "try {"
            "  (Get-NetTCPConnection -LocalPort 21 -State Listen -ErrorAction Stop | Select-Object -First 1) != $null |"
            "    ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    if verbose:
        print(f"[W-21] FTPSVC status={status!r}, port21_listen={listening!r}")

    if not status and listening is None:
        return 0
    if status and status.lower() == "running":
        return 2
    if _truthy(listening) is True:
        return 2
    return 0


def W_22(server: Server, *, verbose: bool = True) -> int:
    """
    W-22 FTP 디렉토리 접근권한 설정
    - 양호: FTP 홈 디렉터리에 Everyone 권한이 없는 경우
    - 취약: Everyone 권한이 있는 경우

    FTP 홈 디렉터리 식별(IIS 설정)부터 환경 의존성이 높아 2를 반환합니다.
    """

    if verbose:
        print("[W-22] 수동 확인 필요: FTP 홈 디렉터리 ACL(Everyone 포함 여부)")
    return 2


def W_23(server: Server, *, verbose: bool = True) -> int:
    """
    W-23 공유 서비스에 대한 익명 접근 제한 설정
    - 양호: 공유 서비스 미사용 또는 익명 인증 사용 안 함
    - 취약: 익명 인증 사용

    IIS/FTP 구성에 따라 달라 2를 반환합니다.
    """

    if verbose:
        print("[W-23] 수동 확인 필요: (IIS/FTP 등) 익명 인증 허용 여부")
    return 2


def W_24(server: Server, *, verbose: bool = True) -> int:
    """
    W-24 FTP 접근 제어 설정
    - 양호: 특정 IP에서만 접속 허용
    - 취약: 접근 제어 미적용

    FTP 서버 구성에 따라 달라 2를 반환합니다.
    """

    if verbose:
        print("[W-24] 수동 확인 필요: FTP IP 제한(allowlist) 설정 여부")
    return 2


def W_25(server: Server, *, verbose: bool = True) -> int:
    """
    W-25 DNS Zone Transfer 설정
    - 양호: DNS 비활성화 또는 전송 미허용/특정 서버만 허용
    - 취약: 위 기준 불만족
    """

    zones = _ps_json(
        server,
        (
            "try {"
            "  Get-DnsServerZone -ErrorAction Stop |"
            "    Select-Object ZoneName,SecureSecondaries,ZoneTransferType |"
            "    ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    rows = zones if isinstance(zones, list) else [zones] if isinstance(zones, dict) else []
    if not rows:
        # DNS 미사용(또는 모듈 없음)
        return 0

    bad = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("ZoneName") or "").strip()
        secure_secondaries = row.get("SecureSecondaries")
        s_val = _int(str(secure_secondaries)) if secure_secondaries is not None else None
        # SecureSecondaries: 0=None, 1=Any, 2=NameServers, 3=Specified(일반적)
        if verbose:
            print(f"[W-25] {name}: SecureSecondaries={s_val!r}, ZoneTransferType={row.get('ZoneTransferType')!r}")
        if s_val == 1:
            bad.append(name)
        elif s_val is None:
            return 2

    return 0 if not bad else 1


def W_26(server: Server, *, verbose: bool = True) -> int:
    """
    W-26 RDS(Remote Data Services) 제거
    - 양호: Windows 2008 이상 등(가이드 기준 중 1개 이상 충족)
    - 취약: 양호 기준 미충족
    """

    ver = _ps_json(
        server,
        (
            "try {"
            "  $v = [System.Environment]::OSVersion.Version;"
            "  [pscustomobject]@{Major=$v.Major; Minor=$v.Minor; Build=$v.Build} | ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    if isinstance(ver, dict):
        major = _int(str(ver.get("Major"))) if ver.get("Major") is not None else None
        if verbose:
            print(f"[W-26] OSVersion={ver!r}")
        if major is not None and major >= 6:
            return 0
    return 2


def W_27(server: Server, *, verbose: bool = True) -> int:
    """
    W-27 최신 Windows OS Build 버전 적용
    - 양호: 최신 Build 설치 + 적용 절차 수립
    - 취약: 미설치 또는 절차 미수립

    최신 여부/절차는 자동 판정이 어려워 빌드 정보를 출력하고 2를 반환합니다.
    """

    reg = _reg_get_many(
        server,
        "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        ["ProductName", "DisplayVersion", "ReleaseId", "CurrentBuild", "CurrentBuildNumber", "UBR"],
    )
    if verbose:
        print(f"[W-27] {reg!r}")
    return 2


def W_29(server: Server, *, verbose: bool = True) -> int:
    """
    W-29 불필요한 SNMP 서비스 구동 점검
    - 양호: SNMP 미사용 또는 Community String 설정 후 사용
    - 취약: 불필요하게 사용

    자동 판정: SNMP 서비스가 구동 중일 때 ValidCommunities가 비어있으면 취약으로 처리합니다.
    """

    svc = _ps_json(
        server,
        "try { Get-Service -Name 'SNMP' -ErrorAction Stop | Select-Object Status | ConvertTo-Json -Compress } catch { }",
    )
    status = str(svc.get("Status") or "").strip() if isinstance(svc, dict) else ""
    if not status or status.lower() != "running":
        return 0

    comm = _ps_json(
        server,
        (
            "try {"
            "  $p='HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\SNMP\\\\Parameters\\\\ValidCommunities';"
            "  $o = Get-ItemProperty -Path $p -ErrorAction Stop;"
            "  ($o.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -ExpandProperty Name) |"
            "    ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    names = comm if isinstance(comm, list) else []
    if verbose:
        print(f"[W-29] SNMP running, communities={names!r}")
    return 0 if names else 1


def W_30(server: Server, *, verbose: bool = True) -> int:
    """
    W-30 SNMP Community String 복잡성 설정
    - 양호: SNMP 미사용 또는 community가 public/private가 아님
    - 취약: SNMP 사용 + community가 public/private
    """

    svc = _ps_json(
        server,
        "try { Get-Service -Name 'SNMP' -ErrorAction Stop | Select-Object Status | ConvertTo-Json -Compress } catch { }",
    )
    status = str(svc.get("Status") or "").strip() if isinstance(svc, dict) else ""
    if not status or status.lower() != "running":
        return 0

    comm = _ps_json(
        server,
        (
            "try {"
            "  $p='HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\SNMP\\\\Parameters\\\\ValidCommunities';"
            "  $o = Get-ItemProperty -Path $p -ErrorAction Stop;"
            "  ($o.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -ExpandProperty Name) |"
            "    ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    names = [str(x) for x in comm] if isinstance(comm, list) else []
    if verbose:
        print(f"[W-30] communities={names!r}")
    lowered = {n.strip().lower() for n in names}
    if not lowered:
        return 1
    return 1 if {"public", "private"} & lowered else 0


def W_31(server: Server, *, verbose: bool = True) -> int:
    """
    W-31 SNMP Access Control 설정
    - 양호: SNMP 미사용 또는 PermittedManagers 설정
    - 취약: 모든 호스트 허용(관리자 미지정)
    """

    svc = _ps_json(
        server,
        "try { Get-Service -Name 'SNMP' -ErrorAction Stop | Select-Object Status | ConvertTo-Json -Compress } catch { }",
    )
    status = str(svc.get("Status") or "").strip() if isinstance(svc, dict) else ""
    if not status or status.lower() != "running":
        return 0

    mgr = _ps_json(
        server,
        (
            "try {"
            "  $p='HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\SNMP\\\\Parameters\\\\PermittedManagers';"
            "  $o = Get-ItemProperty -Path $p -ErrorAction Stop;"
            "  ($o.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -ExpandProperty Value) |"
            "    ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    hosts = [str(x) for x in mgr] if isinstance(mgr, list) else []
    if verbose:
        print(f"[W-31] permitted_managers={hosts!r}")
    return 0 if hosts else 1


def W_32(server: Server, *, verbose: bool = True) -> int:
    """
    W-32 DNS 서비스 구동 점검
    - 양호: DNS 미사용 또는 동적 업데이트 없음
    - 취약: DNS 사용 + 동적 업데이트 설정
    """

    zones = _ps_json(
        server,
        (
            "try {"
            "  Get-DnsServerZone -ErrorAction Stop |"
            "    Select-Object ZoneName,DynamicUpdate |"
            "    ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    rows = zones if isinstance(zones, list) else [zones] if isinstance(zones, dict) else []
    if not rows:
        return 0

    bad = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("ZoneName") or "").strip()
        dyn = str(row.get("DynamicUpdate") or "").strip()
        if verbose:
            print(f"[W-32] {name}: DynamicUpdate={dyn!r}")
        if dyn and dyn.lower() != "none":
            bad.append(name)

    return 0 if not bad else 1


def W_33(server: Server, *, verbose: bool = True) -> int:
    """
    W-33 HTTP/FTP/SMTP 배너 차단
    - 양호: 배너 정보 노출 없음
    - 취약: 배너 정보 노출

    서비스 구성/실서비스 접속 테스트가 필요하여 2를 반환합니다.
    """

    if verbose:
        print("[W-33] 수동 확인 필요: HTTP/FTP/SMTP 배너 노출 여부")
    return 2


def W_35(server: Server, *, verbose: bool = True) -> int:
    """
    W-35 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거
    - 양호/취약 판단이 운영 기준에 따라 달라 DSN 목록을 출력하고 2를 반환합니다.
    """

    dsns = _ps_json(
        server,
        (
            "try {"
            "  $p='HKLM:\\\\SOFTWARE\\\\ODBC\\\\ODBC.INI\\\\ODBC Data Sources';"
            "  $o = Get-ItemProperty -Path $p -ErrorAction Stop;"
            "  ($o.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |"
            "     ForEach-Object { [pscustomobject]@{Name=$_.Name; Driver=$_.Value} }) |"
            "    ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    if verbose:
        print(f"[W-35] System DSN={dsns!r}")
    return 2


def W_37(server: Server, *, verbose: bool = True) -> int:
    """
    W-37 예약된 작업에 의심스러운 명령 등록 점검
    - 주기적 점검 항목으로 자동 판정이 어려워 작업/명령 목록을 출력하고 2를 반환합니다.
    """

    tasks = _ps_json(
        server,
        (
            "try {"
            "  Get-ScheduledTask -ErrorAction Stop |"
            "    ForEach-Object {"
            "      $acts = @();"
            "      foreach ($a in $_.Actions) { $acts += ($a.Execute + ' ' + $a.Arguments) }"
            "      [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Actions=($acts -join '; ')}"
            "    } | ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    if verbose:
        print(f"[W-37] tasks={tasks!r}")
    return 2


def W_38(server: Server, *, verbose: bool = True) -> int:
    """
    W-38 주기적 보안 패치 및 벤더 권고사항 적용
    - 절차/주기까지는 자동 판정이 어려워 최근 설치 업데이트 목록을 출력하고 2를 반환합니다.
    """

    hotfix = _ps_json(
        server,
        (
            "try {"
            "  Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 |"
            "    Select-Object HotFixID,InstalledOn,Description | ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    if verbose:
        print(f"[W-38] hotfix(top20)={hotfix!r}")
    return 2


def W_39(server: Server, *, verbose: bool = True) -> int:
    """
    W-39 백신 프로그램 업데이트
    - 최신 여부/격리망 절차는 자동 판정이 어려워 상태를 출력하고 2를 반환합니다.
    """

    status = _ps_json(
        server,
        (
            "try {"
            "  Get-MpComputerStatus -ErrorAction Stop |"
            "    Select-Object AntivirusEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated |"
            "    ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    if verbose:
        print(f"[W-39] defender_status={status!r}")
    return 2


def W_40(server: Server, *, verbose: bool = True) -> int:
    """
    W-40 정책에 따른 시스템 로깅 설정
    - 권고 기준(조직 정책)에 따라 달라 audit 정책을 출력하고 2를 반환합니다.
    """

    text = _ps(server, "try { (auditpol /get /category:* 2>$null) -join \"`n\" } catch { '' }")
    if verbose:
        print("[W-40] auditpol:")
        print(text.strip())
    return 2


def W_41(server: Server, *, verbose: bool = True) -> int:
    """
    W-41 NTP 및 시각 동기화 설정
    - 양호: 시간 동기화가 설정된 경우
    - 취약: 설정되지 않은 경우

    자동 판정: w32tm Source가 Local CMOS Clock이 아니면 양호로 처리합니다.
    """

    svc = _ps_json(
        server,
        "try { Get-Service -Name 'W32Time' -ErrorAction Stop | Select-Object Status | ConvertTo-Json -Compress } catch { }",
    )
    status = str(svc.get("Status") or "").strip() if isinstance(svc, dict) else ""
    if not status or status.lower() != "running":
        if verbose:
            print(f"[W-41] W32Time status={status!r}")
        return 1

    out = _ps(server, "try { (w32tm /query /status 2>$null) -join \"`n\" } catch { '' }")
    src = ""
    for line in out.splitlines():
        if line.strip().lower().startswith("source:"):
            src = line.split(":", 1)[1].strip()
            break
    if verbose:
        print(f"[W-41] Source={src!r}")
    if not src:
        return 2
    if "local cmos" in src.lower():
        return 1
    return 0


def W_42(server: Server, *, verbose: bool = True) -> int:
    """
    W-42 이벤트 로그 관리 설정
    - 양호: MaxSize >= 10,240KB AND Retention >= 90일
    - 취약: 기준 미만

    레지스트리 기반으로(Application/System/Security) 점검합니다.
    """

    logs = ["Application", "System", "Security"]
    rows: List[dict] = []
    for log in logs:
        reg = _reg_get_many(
            server,
            f"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\{log}",
            ["MaxSize", "Retention"],
        )
        if not reg:
            return 2
        rows.append({"Log": log, **reg})

    threshold_size = 10240 * 1024
    threshold_retention = 90 * 24 * 60 * 60
    ok_all = True
    for row in rows:
        max_size = _int(str(row.get("MaxSize"))) if row.get("MaxSize") is not None else None
        retention = _int(str(row.get("Retention"))) if row.get("Retention") is not None else None
        if verbose:
            print(f"[W-42] {row['Log']}: MaxSize={max_size!r}bytes Retention={retention!r}")
        if max_size is None or retention is None:
            return 2
        ok = max_size >= threshold_size and retention >= threshold_retention
        ok_all &= ok

    return 0 if ok_all else 1


def W_43(server: Server, *, verbose: bool = True) -> int:
    """
    W-43 이벤트 로그 파일 접근 통제 설정
    - 양호: 로그 디렉터리 ACL에 Everyone 권한이 없는 경우
    - 취약: Everyone 권한이 있는 경우
    """

    out = _ps(
        server,
        "try { icacls \"$env:SystemRoot\\System32\\winevt\\Logs\" } catch { '' }",
    )
    if not out.strip():
        return 2
    if verbose:
        print(out.strip())
    lowered = out.lower()
    return 1 if ("everyone" in lowered or "모든 사람" in out) else 0


def W_44(server: Server, *, verbose: bool = True) -> int:
    """
    W-44 원격으로 액세스할 수 있는 레지스트리 경로
    - 양호: Remote Registry 서비스 중지
    - 취약: Remote Registry 서비스 사용
    """

    svc = _ps_json(
        server,
        "try { Get-Service -Name 'RemoteRegistry' -ErrorAction Stop | Select-Object Status | ConvertTo-Json -Compress } catch { }",
    )
    status = str(svc.get("Status") or "").strip() if isinstance(svc, dict) else ""
    if verbose:
        print(f"[W-44] RemoteRegistry status={status!r}")
    if not status:
        return 0
    return 0 if status.lower() != "running" else 1


def W_45(server: Server, *, verbose: bool = True) -> int:
    """
    W-45 백신 프로그램 설치
    - 양호: 백신 설치
    - 취약: 미설치
    """

    av = _ps_json(
        server,
        (
            "try {"
            "  Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop |"
            "    Select-Object displayName,productState,pathToSignedProductExe |"
            "    ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    if verbose:
        print(f"[W-45] SecurityCenter2={av!r}")
    if isinstance(av, list) and av:
        return 0
    if isinstance(av, dict) and av:
        return 0

    defender = _ps_json(
        server,
        "try { Get-MpComputerStatus -ErrorAction Stop | Select-Object AntivirusEnabled | ConvertTo-Json -Compress } catch { }",
    )
    if verbose:
        print(f"[W-45] Defender={defender!r}")
    enabled = None
    if isinstance(defender, dict):
        enabled = _truthy(defender.get("AntivirusEnabled"))
    if enabled is True:
        return 0
    return 1


def W_46(server: Server, *, verbose: bool = True) -> int:
    """
    W-46 SAM 파일 접근 통제 설정
    - 양호: Allow ACE가 Administrators/System만 존재
    - 취약: 그 외 계정/그룹에 권한 존재
    """

    acls = _ps_json(
        server,
        (
            "try {"
            "  $path = Join-Path $env:SystemRoot 'System32\\config\\SAM';"
            "  $acl = Get-Acl -LiteralPath $path;"
            "  $out=@();"
            "  foreach ($ace in $acl.Access) {"
            "    $sid=$null;"
            "    try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $ace.IdentityReference.Value }"
            "    $out += [pscustomobject]@{Sid=$sid; Type=$ace.AccessControlType.ToString(); Rights=$ace.FileSystemRights.ToString(); Inherited=$ace.IsInherited};"
            "  }"
            "  $out | ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    rows = acls if isinstance(acls, list) else [acls] if isinstance(acls, dict) else []
    if not rows:
        return 2

    allowed = {"S-1-5-18", _ADMIN_SID}
    bad = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("Type") or "").strip().lower() != "allow":
            continue
        sid = str(row.get("Sid") or "").strip()
        if sid and sid not in allowed:
            bad.append(sid)

    if verbose:
        print(f"[W-46] allow_sids={bad!r} (allowed={sorted(allowed)})")
    return 0 if not bad else 1


def W_47(server: Server, *, verbose: bool = True) -> int:
    """
    W-47 화면 보호기 설정
    - 양호: ScreenSaver 활성 + timeout<=10분 + 해제 암호 사용
    - 취약: 미설정/timeout>10분/암호 미사용
    """

    # 우선 정책(HKLM) 확인, 없으면 현재 사용자(HKCU) 확인
    policy = _reg_get_many(
        server,
        "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop",
        ["ScreenSaveActive", "ScreenSaverIsSecure", "ScreenSaveTimeOut"],
    )
    current = None
    if not policy:
        current = _reg_get_many(
            server,
            "HKCU:\\Control Panel\\Desktop",
            ["ScreenSaveActive", "ScreenSaverIsSecure", "ScreenSaveTimeOut"],
        )

    src = policy if policy else current
    if verbose:
        print(f"[W-47] policy={policy!r} current={current!r}")
    if not src:
        return 2

    active = str(src.get("ScreenSaveActive") or "").strip()
    secure = str(src.get("ScreenSaverIsSecure") or "").strip()
    timeout = _int(str(src.get("ScreenSaveTimeOut"))) if src.get("ScreenSaveTimeOut") is not None else None
    if timeout is None:
        return 2

    ok = active == "1" and secure == "1" and 0 < timeout <= 600
    return 0 if ok else 1


def W_58(server: Server, *, verbose: bool = True) -> int:
    """
    W-58 사용자별 홈 디렉터리 권한 설정
    - 양호: (All Users/Default User 제외) 홈 디렉터리에 Everyone 권한이 없는 경우
    - 취약: Everyone 권한이 있는 경우
    """

    data = _ps_json(
        server,
        (
            "try {"
            "  $root = Join-Path $env:SystemDrive 'Users';"
            "  if (-not (Test-Path $root)) { $root = Join-Path $env:SystemDrive 'Documents and Settings' }"
            "  $skip = @('All Users','Default','Default User','Public','defaultuser0');"
            "  $out=@();"
            "  Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {"
            "    if ($skip -contains $_.Name) { return }"
            "    $has=$false;"
            "    try {"
            "      $acl = Get-Acl -LiteralPath $_.FullName;"
            "      foreach ($ace in $acl.Access) {"
            "        $sid=$null;"
            "        try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }"
            "        $name = $ace.IdentityReference.Value;"
            "        if ($sid -eq 'S-1-1-0' -or $name -match 'Everyone|모든 사람') { $has=$true }"
            "      }"
            "      $out += [pscustomobject]@{Path=$_.FullName; HasEveryone=$has};"
            "    } catch {"
            "      $out += [pscustomobject]@{Path=$_.FullName; Error=$_.Exception.Message};"
            "    }"
            "  }"
            "  $out | ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    rows = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    if not rows:
        return 2

    has_everyone = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("Error"):
            return 2
        if _truthy(row.get("HasEveryone")) is True:
            has_everyone = True
            if verbose:
                print(f"[W-58] Everyone 권한: {row.get('Path')}")
    return 0 if not has_everyone else 1


def W_61(server: Server, *, verbose: bool = True) -> int:
    """
    W-61 파일 및 디렉토리 보호
    - 양호: NTFS 사용
    - 취약: FAT 사용
    """

    vols = _ps_json(
        server,
        (
            "try {"
            "  Get-Volume -ErrorAction Stop | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } |"
            "    Select-Object DriveLetter,FileSystem | ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    rows = vols if isinstance(vols, list) else [vols] if isinstance(vols, dict) else []
    if not rows:
        return 2

    bad = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        fs = str(row.get("FileSystem") or "").strip().upper()
        dl = str(row.get("DriveLetter") or "").strip().upper()
        if verbose:
            print(f"[W-61] {dl}: {fs}")
        if fs.startswith("FAT"):
            bad.append(dl)
    return 0 if not bad else 1


def W_62(server: Server, *, verbose: bool = True) -> int:
    """
    W-62 시작 프로그램 목록 분석
    - 양호/취약은 운영 점검 주기/정책에 따라 달라 시작 항목을 출력하고 2를 반환합니다.
    """

    data = _ps_json(
        server,
        (
            "try {"
            "  $paths = @("
            "    'HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',"
            "    'HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce',"
            "    'HKCU:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',"
            "    'HKCU:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce'"
            "  );"
            "  $out=@();"
            "  foreach ($p in $paths) {"
            "    try {"
            "      $o = Get-ItemProperty -Path $p -ErrorAction Stop;"
            "      foreach ($prop in $o.PSObject.Properties) {"
            "        if ($prop.Name -like 'PS*') { continue }"
            "        $out += [pscustomobject]@{Path=$p; Name=$prop.Name; Value=$prop.Value}"
            "      }"
            "    } catch { }"
            "  }"
            "  $out | ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    if verbose:
        print(f"[W-62] startup={data!r}")
    return 2


def W_63(server: Server, *, verbose: bool = True) -> int:
    """
    W-63 도메인 컨트롤러-사용자의 시간 동기화
    - 양호: 최대 허용 오차값 <= 5분(300초)
    - 취약: 5분 초과
    """

    reg = _reg_get(server, "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config", "MaxAllowedPhaseOffset")
    val = _int(str(reg)) if reg is not None else None
    if verbose:
        print(f"[W-63] MaxAllowedPhaseOffset={val!r}")
    if val is None:
        return 2
    return 0 if val <= 300 else 1


def W_64(server: Server, *, verbose: bool = True) -> int:
    """
    W-64 윈도우 방화벽 설정
    - 양호: 방화벽 사용(모든 프로필 Enabled=True)
    - 취약: 일부라도 사용 안 함
    """

    profiles = _ps_json(
        server,
        (
            "try {"
            "  Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
            "} catch { }"
        ),
    )
    rows = profiles if isinstance(profiles, list) else [profiles] if isinstance(profiles, dict) else []
    if not rows:
        if verbose:
            print("[W-64] Get-NetFirewallProfile 결과 없음(수동 확인 필요)")
        return 2

    enabled_all = True
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("Name") or "").strip()
        enabled = _truthy(row.get("Enabled"))
        if verbose:
            print(f"[W-64] {name}: Enabled={enabled!r}")
        if enabled is not True:
            enabled_all = False
    return 0 if enabled_all else 1


CHECKS: Dict[str, Callable[..., int]] = {
    "W-01": W_01,
    "W-02": W_02,
    "W-03": W_03,
    "W-06": W_06,
    "W-07": W_07,
    "W-10": W_10,
    "W-11": W_11,
    "W-12": W_12,
    "W-13": W_13,
    "W-14": W_14,
    "W-15": W_15,
    "W-16": W_16,
    "W-17": W_17,
    "W-18": W_18,
    "W-19": W_19,
    "W-20": W_20,
    "W-21": W_21,
    "W-22": W_22,
    "W-23": W_23,
    "W-24": W_24,
    "W-25": W_25,
    "W-26": W_26,
    "W-27": W_27,
    "W-28": W_28,
    "W-29": W_29,
    "W-30": W_30,
    "W-31": W_31,
    "W-32": W_32,
    "W-33": W_33,
    "W-34": W_34,
    "W-35": W_35,
    "W-36": W_36,
    "W-37": W_37,
    "W-38": W_38,
    "W-39": W_39,
    "W-40": W_40,
    "W-41": W_41,
    "W-42": W_42,
    "W-43": W_43,
    "W-04": W_04,
    "W-05": W_05,
    "W-08": W_08,
    "W-09": W_09,
    "W-44": W_44,
    "W-45": W_45,
    "W-46": W_46,
    "W-47": W_47,
    "W-48": W_48,
    "W-49": W_49,
    "W-50": W_50,
    "W-51": W_51,
    "W-52": W_52,
    "W-53": W_53,
    "W-54": W_54,
    "W-55": W_55,
    "W-56": W_56,
    "W-57": W_57,
    "W-58": W_58,
    "W-59": W_59,
    "W-60": W_60,
    "W-61": W_61,
    "W-62": W_62,
    "W-63": W_63,
    "W-64": W_64,
}
