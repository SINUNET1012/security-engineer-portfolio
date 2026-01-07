from __future__ import annotations

from typing import Callable, Dict

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


def _manual(code: str, title: str, hint: str, *, verbose: bool) -> int:
    if verbose:
        print(f"[{code}] 수동 확인 필요: {title}")
        if hint:
            print(f" - 확인: {hint}")
    return 2


def S_01(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-01",
        "보안장비 Default 계정 변경",
        "초기/기본 관리자 계정(예: admin 등) 존재/활성 여부 및 계정명 변경 여부",
        verbose=verbose,
    )


def S_02(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-02",
        "비밀번호 관리정책 설정",
        "최소 길이/복잡도/만료/재사용 제한 등 비밀번호 정책 설정 여부",
        verbose=verbose,
    )


def S_03(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-03",
        "보안장비 계정별 권한 설정",
        "계정별 역할(Role)·권한이 최소권한 원칙으로 구성되어 있는지 확인",
        verbose=verbose,
    )


def S_04(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-04",
        "보안장비 계정 관리",
        "불필요/미사용 계정 제거, 퇴직/부서이동 계정 정리, 공유계정 최소화 여부",
        verbose=verbose,
    )


def S_05(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-05",
        "계정 잠금 임계값 설정",
        "로그인 실패 횟수 기반 계정 잠금(또는 지연) 정책 설정 여부",
        verbose=verbose,
    )


def S_06(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-06",
        "보안 장비 원격 관리 접근 통제",
        "관리 접속 허용 IP/망(ACL) 제한 및 불필요한 원격관리 채널 차단 여부",
        verbose=verbose,
    )


def S_07(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-07",
        "보안장비 보안 접속",
        "관리 접속은 SSH/HTTPS 등 안전한 프로토콜만 사용(텔넷/HTTP 비활성화) 여부",
        verbose=verbose,
    )


def S_08(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-08",
        "세션 종료 시간 설정",
        "유휴 시간(Session Timeout) 설정 여부(예: 10~15분 등 정책 기준)",
        verbose=verbose,
    )


def S_09(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-09",
        "주기적 보안 패치 및 벤더 권고사항 적용",
        "펌웨어/시그니처/패치 최신화 및 벤더 권고사항 적용 프로세스 존재 여부",
        verbose=verbose,
    )


def S_10(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-10",
        "보안장비 로그 설정",
        "정책 위반/관리자 행위/시스템 이벤트 등 로깅 범위·수준 설정 여부",
        verbose=verbose,
    )


def S_11(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-11",
        "보안장비 로그 보관",
        "로그 보관 기간/용량/순환 정책 설정 및 무결성 보장 여부",
        verbose=verbose,
    )


def S_12(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-12",
        "보안장비 정책 백업 설정",
        "정책/설정 정기 백업(자동/수동), 백업 보관 위치 및 접근통제 여부",
        verbose=verbose,
    )


def S_13(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-13",
        "원격 로그 서버 사용",
        "Syslog/SIEM 등 원격 로그 서버로 전송 설정 여부(필요 시 TLS 등 보호 포함)",
        verbose=verbose,
    )


def S_14(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-14",
        "NTP 및 시각 동기화 설정",
        "NTP 서버 설정 및 동기화 상태(오프셋/스트라텀 등) 확인",
        verbose=verbose,
    )


def S_15(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-15",
        "정책 관리",
        "정책 변경 승인/이력/검토, 불필요·중복 정책 정리 및 주기적 점검 여부",
        verbose=verbose,
    )


def S_16(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-16",
        "NAT 설정",
        "불필요 NAT 제거, 목적에 맞는 NAT 룰 구성 및 예외/우회 설정 점검",
        verbose=verbose,
    )


def S_17(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-17",
        "DMZ 설정",
        "DMZ 분리 및 외부/내부 간 정책 최소화(필요 포트만 허용) 여부",
        verbose=verbose,
    )


def S_18(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-18",
        "최소한의 서비스만 제공",
        "불필요 서비스/데몬/관리 포트 비활성화(정책/운영 필요 범위 내 최소화) 여부",
        verbose=verbose,
    )


def S_19(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-19",
        "이상징후 탐지 모니터링 수행",
        "탐지 이벤트 모니터링/알림(메일·SMS·SIEM 연동 등) 및 대응 절차 존재 여부",
        verbose=verbose,
    )


def S_20(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-20",
        "장비 사용량 검토",
        "CPU/메모리/세션/처리량 등 사용량 모니터링 및 용량 계획/임계치 알림 설정 여부",
        verbose=verbose,
    )


def S_21(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-21",
        "SNMP 서비스 확인",
        "NMS 연동 등 필요가 없다면 SNMP 서비스를 중지(필요 시에는 접근통제/Community 보호)",
        verbose=verbose,
    )


def S_22(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-22",
        "SNMP Community String 복잡성 설정",
        "SNMP 미사용 또는(사용 시) 기본값(public/private) 금지, 예측 어려운 문자열 사용, 가능하면 SNMPv3 권장",
        verbose=verbose,
    )


def S_23(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "S-23",
        "유해 트래픽 탐지/차단 정책 설정",
        "장비 특성(방화벽/IPS/WAF 등)에 맞게 유해 트래픽 탐지·차단 정책 적용 및 최신 시그니처 유지",
        verbose=verbose,
    )


CHECKS: Dict[str, Callable[..., int]] = {
    "S-01": S_01,
    "S-02": S_02,
    "S-03": S_03,
    "S-04": S_04,
    "S-05": S_05,
    "S-06": S_06,
    "S-07": S_07,
    "S-08": S_08,
    "S-09": S_09,
    "S-10": S_10,
    "S-11": S_11,
    "S-12": S_12,
    "S-13": S_13,
    "S-14": S_14,
    "S-15": S_15,
    "S-16": S_16,
    "S-17": S_17,
    "S-18": S_18,
    "S-19": S_19,
    "S-20": S_20,
    "S-21": S_21,
    "S-22": S_22,
    "S-23": S_23,
}

