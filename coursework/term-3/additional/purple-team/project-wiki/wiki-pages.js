(() => {
  const currentScript = document.currentScript;
  try {
    window.WIKI_BASE_URL = currentScript ? new URL('.', currentScript.src).href : new URL('.', window.location.href).href;
  } catch (_) {
    window.WIKI_BASE_URL = new URL('.', window.location.href).href;
  }
  window.WIKI_PAGES = [
    {
        "title":  "3차 퍼플팀 프로젝트 개념 총정리",
        "href":  "index.html",
        "summary":  "프로젝트 전체 흐름과 기술/운영 개념을 한 문서로 정리합니다."
    },
    {
        "title":  "Ansible",
        "href":  "docs/tech/ansible.html",
        "summary":  "구축 및 대응 정책을 반복 가능하게 만드는 자동화 엔진입니다."
    },
    {
        "title":  "CAPE",
        "href":  "docs/tech/cape.html",
        "summary":  "악성코드 동적 분석 실습을 위한 샌드박스 구성 요소입니다."
    },
    {
        "title":  "Elasticsearch",
        "href":  "docs/tech/elasticsearch.html",
        "summary":  "검색/집계 중심의 저장 계층으로 탐지 분석의 기반입니다."
    },
    {
        "title":  "Filebeat / Syslog",
        "href":  "docs/tech/filebeat-syslog.html",
        "summary":  "로그 수집 계층의 역할과 안정 전송 체크포인트를 정리합니다."
    },
    {
        "title":  "GNS3 / OSPF / IPv6",
        "href":  "docs/tech/gns3-network.html",
        "summary":  "네트워크 실습 토폴로지와 라우팅 동작 이해를 위한 학습 요소입니다."
    },
    {
        "title":  "Kibana",
        "href":  "docs/tech/kibana.html",
        "summary":  "탐지 결과 확인, 추세 분석, 증적 화면 제공을 담당합니다."
    },
    {
        "title":  "Logstash",
        "href":  "docs/tech/logstash.html",
        "summary":  "로그 파싱/정규화/가공을 담당하는 ETL 계층입니다."
    },
    {
        "title":  "ModSecurity",
        "href":  "docs/tech/modsecurity.html",
        "summary":  "웹 요청/응답 기반 공격을 탐지/차단하는 WAF 엔진입니다."
    },
    {
        "title":  "Nessus",
        "href":  "docs/tech/nessus.html",
        "summary":  "취약점 진단 결과를 탐지 룰 설계 근거로 활용하는 스캐닝 도구입니다."
    },
    {
        "title":  "pfSense",
        "href":  "docs/tech/pfsense.html",
        "summary":  "경계 네트워크 제어 지점으로 차단 정책을 반영하는 장비입니다."
    },
    {
        "title":  "Suricata",
        "href":  "docs/tech/suricata.html",
        "summary":  "네트워크 구간 공격을 시그니처 기반으로 탐지하는 NIDS/IPS 엔진입니다."
    },
    {
        "title":  "Wazuh + Auditd",
        "href":  "docs/tech/wazuh-auditd.html",
        "summary":  "호스트 내부 행위와 시스템 로그를 탐지하는 HIDS 계층입니다."
    },
    {
        "title":  "고도화 로드맵",
        "href":  "docs/roadmap.html",
        "summary":  "단기/중기 개선 과제를 우선순위 기반으로 정리합니다."
    },
    {
        "title":  "공격-탐지-대응 시나리오",
        "href":  "docs/attack-scenarios.html",
        "summary":  "공격 유형별 로그/탐지/대응/증적 체인을 정의합니다."
    },
    {
        "title":  "관련 문서",
        "href":  "docs/references.html",
        "summary":  "저장소 내 주요 문서와 세부 자료를 연결하는 레퍼런스 허브입니다."
    },
    {
        "title":  "기술 개념 백과(허브)",
        "href":  "docs/tech-index.html",
        "summary":  "각 기술 요소의 상세 문서로 이동하는 허브 페이지입니다."
    },
    {
        "title":  "데이터 필드 표준",
        "href":  "docs/data-model.html",
        "summary":  "탐지 품질을 위한 공통 필드 스키마와 검증 규칙을 정의합니다."
    },
    {
        "title":  "룰 설계 원칙",
        "href":  "docs/rule-design.html",
        "summary":  "탐지 룰의 생성/검증/운영/폐기 원칙을 정의합니다."
    },
    {
        "title":  "목표와 범위",
        "href":  "docs/goals-scope.html",
        "summary":  "무엇을 구현하고 무엇을 제외할지 프로젝트 경계를 정의합니다."
    },
    {
        "title":  "발표용 핵심 스토리",
        "href":  "docs/presentation-story.html",
        "summary":  "프로젝트 발표 시 전달해야 할 핵심 메시지와 흐름을 정리합니다."
    },
    {
        "title":  "용어 정리",
        "href":  "docs/glossary.html",
        "summary":  "프로젝트 공통 커뮤니케이션을 위한 핵심 용어 사전입니다."
    },
    {
        "title":  "운영 Runbook",
        "href":  "docs/runbook.html",
        "summary":  "일일/주간/시연 전 운영 점검 절차를 실행 가능한 단계로 정리합니다."
    },
    {
        "title":  "운영 품질 KPI",
        "href":  "docs/kpi.html",
        "summary":  "수집/정규화/탐지/대응 품질을 수치로 관리하는 지표 체계입니다."
    },
    {
        "title":  "운영/협업 체계",
        "href":  "docs/ops-collaboration.html",
        "summary":  "서버/네트워크/레드/퍼플 간 협업 규칙과 산출물 체계를 정의합니다."
    },
    {
        "title":  "자동화/안전장치",
        "href":  "docs/automation-safety.html",
        "summary":  "자동 대응 자동화의 적용 원칙과 안전장치를 정리합니다."
    },
    {
        "title":  "전체 아키텍처 흐름",
        "href":  "docs/architecture-flow.html",
        "summary":  "로그 생성부터 탐지/대응/증적까지의 end-to-end 파이프라인을 설명합니다."
    },
    {
        "title":  "트러블슈팅 가이드",
        "href":  "docs/troubleshooting.html",
        "summary":  "자주 발생하는 장애 증상과 점검 순서를 정리한 운영 가이드입니다."
    },
    {
        "title":  "퍼플위키: 프로젝트 자료 인덱스",
        "href":  "article-asset-index.html",
        "summary":  "저장소 파일/폴더/링크/통계를 탐색합니다."
    },
    {
        "title":  "프로젝트 개요",
        "href":  "docs/overview.html",
        "summary":  "3차 퍼플팀 프로젝트의 목적, 배경, 성공 조건을 정의합니다."
    },
    {
        "title":  "프로젝트 세부 흐름",
        "href":  "docs/detailed-flow.html",
        "summary":  "Phase 단위로 구현/검증/운영 전환 절차를 정의합니다."
    }
];
})();
