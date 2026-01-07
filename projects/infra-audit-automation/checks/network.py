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


def _manual(code: str, title: str, checks: list[str], *, verbose: bool) -> int:
    if verbose:
        print(f"[{code}] 수동 확인 필요: {title}")
        for line in checks:
            if line:
                print(f" - {line}")
    return 2


def N_01(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-01",
        "비밀번호 설정",
        [
            "관리자/운영 계정 비밀번호 설정 여부(기본값/공백 금지)",
            "벤더별 CLI/GUI에서 계정 목록 및 인증 정책 확인",
        ],
        verbose=verbose,
    )


def N_02(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-02",
        "비밀번호 복잡성 설정",
        [
            "최소 길이/복잡도/만료/재사용 제한 정책 설정 여부",
            "가능하면 AAA(RADIUS/TACACS+) 연동 정책도 함께 확인",
        ],
        verbose=verbose,
    )


def N_03(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-03",
        "암호화된 비밀번호 사용",
        [
            "평문(보이는) 비밀번호 저장/표시 금지",
            "예: Cisco 계열이면 `enable secret` 사용, `service password-encryption` 설정 여부 확인",
        ],
        verbose=verbose,
    )


def N_04(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-04",
        "계정 잠금 임계값 설정",
        [
            "로그인 실패 횟수 기반 잠금/지연 정책 설정 여부",
            "AAA 연동 시(예: TACACS+/RADIUS) 정책이 어디에 적용되는지 함께 확인",
        ],
        verbose=verbose,
    )


def N_05(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-05",
        "사용자·명령어별 권한 설정",
        [
            "역할 기반 권한/명령어별 권한(Role/Privilege) 최소권한 적용 여부",
            "예: Cisco 계열이면 privilege 레벨/AAA authorization 확인",
        ],
        verbose=verbose,
    )


def N_06(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-06",
        "VTY 접근(ACL) 설정",
        [
            "원격관리(SSH/HTTPS) 허용 IP/망을 ACL로 제한했는지 확인",
            "예: Cisco 계열이면 `line vty`에 `access-class <ACL> in` 적용 여부",
        ],
        verbose=verbose,
    )


def N_07(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-07",
        "Session Timeout 설정",
        [
            "유휴 시간(Session/Idle) 타임아웃 설정 여부",
            "예: Cisco 계열이면 `line vty`의 `exec-timeout <min> <sec>` 확인",
        ],
        verbose=verbose,
    )


def N_08(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-08",
        "VTY 접속 시 안전한 프로토콜 사용",
        [
            "텔넷(plain) 비활성화 및 SSH 등 암호화 채널만 허용 여부",
            "예: Cisco 계열이면 `transport input ssh`(또는 `transport input none`) 확인",
        ],
        verbose=verbose,
    )


def N_09(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-09",
        "불필요한 보조 입출력 포트 사용 금지",
        [
            "AUX/CONSOLE 등 보조 포트 사용 정책 및 미사용 시 비활성화/접근통제 여부",
            "예: Cisco 계열이면 `line aux 0` 설정(패스워드/타임아웃/비활성화) 확인",
        ],
        verbose=verbose,
    )


def N_10(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-10",
        "로그인 시 경고 메시지 설정",
        [
            "로그인 배너/경고 문구 설정 여부",
            "예: Cisco 계열이면 `banner motd`/`banner login` 확인",
        ],
        verbose=verbose,
    )


def N_11(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-11",
        "원격로그 서버 사용",
        [
            "원격 Syslog/SIEM 등으로 로그 전송 설정 여부",
            "예: Cisco 계열이면 `logging host <ip>`/`logging trap`/`logging source-interface` 확인",
        ],
        verbose=verbose,
    )


def N_12(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-12",
        "주기적 보안 패치 및 벤더 권고사항 적용",
        [
            "펌웨어/OS 버전 최신화 및 정기 점검/업데이트 정책 존재 여부",
            "벤더 권고(보안 공지, CVE) 대응 프로세스 확인",
        ],
        verbose=verbose,
    )


def N_13(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-13",
        "로깅 버퍼 크기 설정",
        [
            "장비 내부 로깅 버퍼 크기 적정 설정 여부",
            "예: Cisco 계열이면 `logging buffered <size>` 확인",
        ],
        verbose=verbose,
    )


def N_14(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-14",
        "정책에 따른 로깅 설정",
        [
            "보안 정책에 맞는 로깅 레벨/대상(관리자 행위/정책 변경/보안 이벤트 등) 설정 여부",
            "예: Cisco 계열이면 `logging trap <level>`/시설 정책 기준 확인",
        ],
        verbose=verbose,
    )


def N_15(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-15",
        "NTP 및 시각 동기화 설정",
        [
            "NTP 서버 설정 및 동기화 상태 확인",
            "예: Cisco 계열이면 `ntp server <ip>`/`show ntp status` 확인",
        ],
        verbose=verbose,
    )


def N_16(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-16",
        "Timestamp 로그 설정",
        [
            "로그에 타임스탬프가 기록되도록 설정 여부",
            "예: Cisco 계열이면 `service timestamps log datetime msec` 확인",
        ],
        verbose=verbose,
    )


def N_17(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-17",
        "SNMP 서비스 확인",
        [
            "NMS 연동 등 필요 없으면 SNMP 비활성화",
            "필요 시에도 접근통제(ACL) + v3(암호화) 우선 + community 보호 확인",
        ],
        verbose=verbose,
    )


def N_18(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-18",
        "SNMP Community String 복잡성 설정",
        [
            "기본값(public/private) 금지, 예측 어려운 문자열 사용, 가능하면 SNMPv3 권장",
            "커뮤니티 노출/재사용/공유 여부 확인",
        ],
        verbose=verbose,
    )


def N_19(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-19",
        "SNMP ACL 설정",
        [
            "SNMP 요청 허용 대상(관리 서버)만 ACL로 제한했는지 확인",
            "예: Cisco 계열이면 `snmp-server community <str> RO <ACL>` 형태 확인",
        ],
        verbose=verbose,
    )


def N_20(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-20",
        "SNMP Community 권한 설정",
        [
            "불필요한 RW 권한 금지(가능하면 RO만), 최소권한 적용",
            "SNMPv3 사용 시 사용자별 권한(authPriv 등) 구성 확인",
        ],
        verbose=verbose,
    )


def N_21(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-21",
        "TFTP 서비스 차단",
        [
            "불필요한 TFTP 서버/클라이언트 기능 비활성화 또는 접근 통제",
            "예: Cisco 계열이면 `tftp-server` 설정 존재 여부 확인(미사용 시 제거)",
        ],
        verbose=verbose,
    )


def N_22(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-22",
        "Spoofing 방지 필터링 적용",
        [
            "IP 스푸핑 방지(예: uRPF, ingress ACL 등) 설정 여부",
            "예: Cisco 계열이면 인터페이스 `ip verify unicast source reachable-via` 적용 여부 확인",
        ],
        verbose=verbose,
    )


def N_23(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-23",
        "DDoS 공격 방어 설정 또는 DDoS 장비 사용",
        [
            "DDoS 탐지/차단 정책 또는 전용 장비/서비스 연동 여부",
            "ACL/CoPP/Rate-limit/Blackhole/FlowSpec 등 조직 표준 확인",
        ],
        verbose=verbose,
    )


def N_24(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-24",
        "사용하지 않는 인터페이스 비활성화",
        [
            "미사용 포트 shutdown/disable 및 라벨링/정책 관리 여부",
            "예: Cisco 계열이면 `interface ...` + `shutdown` 확인",
        ],
        verbose=verbose,
    )


def N_25(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-25",
        "TCP Keepalive 서비스 설정",
        [
            "불필요 세션 유지 방지: keepalive 설정 여부",
            "예: Cisco 계열이면 `service tcp-keepalives-in/out` 확인",
        ],
        verbose=verbose,
    )


def N_26(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-26",
        "Finger 서비스 차단",
        [
            "미사용 Finger 서비스 비활성화",
            "예: Cisco 계열이면 `no service finger` 확인",
        ],
        verbose=verbose,
    )


def N_27(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-27",
        "웹 서비스 차단",
        [
            "불필요한 HTTP/HTTPS 관리 웹서비스 비활성화(필요 시 접근통제/HTTPS만 허용)",
            "예: Cisco 계열이면 `no ip http server`/`no ip http secure-server` 확인",
        ],
        verbose=verbose,
    )


def N_28(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-28",
        "TCP/UDP small 서비스 차단",
        [
            "미사용 TCP/UDP small-servers 비활성화",
            "예: Cisco 계열이면 `no service tcp-small-servers`/`no service udp-small-servers` 확인",
        ],
        verbose=verbose,
    )


def N_29(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-29",
        "Bootp 서비스 차단",
        [
            "미사용 BOOTP 서비스 비활성화",
            "예: Cisco 계열이면 `no ip bootp server` 확인",
        ],
        verbose=verbose,
    )


def N_30(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-30",
        "CDP 서비스 차단",
        [
            "불필요한 CDP 비활성화(네트워크 정보 노출 방지)",
            "예: Cisco 계열이면 `no cdp run` 및 필요 시 인터페이스 단위 `no cdp enable` 확인",
        ],
        verbose=verbose,
    )


def N_31(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-31",
        "Directed-broadcast 차단",
        [
            "IP directed broadcast 비활성화(스머프 공격 등 방지)",
            "예: Cisco 계열이면 인터페이스 `no ip directed-broadcast` 확인",
        ],
        verbose=verbose,
    )


def N_32(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-32",
        "Source Routing 차단",
        [
            "Source Route 패킷 처리 비활성화",
            "예: Cisco 계열이면 `no ip source-route` 확인",
        ],
        verbose=verbose,
    )


def N_33(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-33",
        "Proxy ARP 차단",
        [
            "불필요한 Proxy ARP 비활성화",
            "예: Cisco 계열이면 인터페이스 `no ip proxy-arp` 확인",
        ],
        verbose=verbose,
    )


def N_34(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-34",
        "ICMP unreachable, redirect 차단",
        [
            "불필요한 ICMP unreachable/redirect 응답 제한 또는 비활성화",
            "예: Cisco 계열이면 인터페이스 `no ip redirects`/`no ip unreachables` 확인",
        ],
        verbose=verbose,
    )


def N_35(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-35",
        "identd 서비스 차단",
        [
            "identd 비활성화",
            "예: Cisco 계열이면 `no ip identd` 확인",
        ],
        verbose=verbose,
    )


def N_36(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-36",
        "Domain Lookup 차단",
        [
            "불필요한 DNS lookup 비활성화(오타 시 장시간 대기 방지 등)",
            "예: Cisco 계열이면 `no ip domain-lookup` 확인",
        ],
        verbose=verbose,
    )


def N_37(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-37",
        "pad 차단",
        [
            "PAD(Packet Assembler/Disassembler) 서비스 비활성화",
            "예: Cisco 계열이면 `no service pad` 확인",
        ],
        verbose=verbose,
    )


def N_38(server: Server, *, verbose: bool = True) -> int:
    return _manual(
        "N-38",
        "mask-reply 차단",
        [
            "ICMP mask-reply 비활성화",
            "예: Cisco 계열이면 `no ip mask-reply` 확인",
        ],
        verbose=verbose,
    )


CHECKS: Dict[str, Callable[..., int]] = {
    "N-01": N_01,
    "N-02": N_02,
    "N-03": N_03,
    "N-04": N_04,
    "N-05": N_05,
    "N-06": N_06,
    "N-07": N_07,
    "N-08": N_08,
    "N-09": N_09,
    "N-10": N_10,
    "N-11": N_11,
    "N-12": N_12,
    "N-13": N_13,
    "N-14": N_14,
    "N-15": N_15,
    "N-16": N_16,
    "N-17": N_17,
    "N-18": N_18,
    "N-19": N_19,
    "N-20": N_20,
    "N-21": N_21,
    "N-22": N_22,
    "N-23": N_23,
    "N-24": N_24,
    "N-25": N_25,
    "N-26": N_26,
    "N-27": N_27,
    "N-28": N_28,
    "N-29": N_29,
    "N-30": N_30,
    "N-31": N_31,
    "N-32": N_32,
    "N-33": N_33,
    "N-34": N_34,
    "N-35": N_35,
    "N-36": N_36,
    "N-37": N_37,
    "N-38": N_38,
}

