$ErrorActionPreference = 'Stop'

$docsRoot = Join-Path $PSScriptRoot 'docs'
$now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

function Escape-Html {
  param([string]$Text)
  if ($null -eq $Text) { return '' }
  return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function Get-TagInnerText {
  param(
    [string]$Raw,
    [string]$Tag,
    [string]$ClassName
  )

  $pattern = "<$Tag class=""$ClassName"">([\s\S]*?)</$Tag>"
  $m = [regex]::Match($Raw, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if ($m.Success) { return $m.Groups[1].Value.Trim() }
  return ''
}

function Get-H1Text {
  param([string]$Raw)
  $m = [regex]::Match($Raw, '<h1>([\s\S]*?)</h1>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if ($m.Success) { return $m.Groups[1].Value.Trim() }
  return ''
}

function Get-RelatedLinks {
  param([string]$Raw)

  $section = [regex]::Match(
    $Raw,
    '<section id="related"[\s\S]*?</section>',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
  )

  if (-not $section.Success) { return @() }

  $links = [regex]::Matches(
    $section.Value,
    '<a\s+href="([^"]+)">([^<]+)</a>',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
  )

  $items = @()
  foreach ($link in $links) {
    $items += [PSCustomObject]@{
      href = $link.Groups[1].Value
      text = $link.Groups[2].Value
    }
  }
  return $items
}

function Get-ConceptPoints {
  param(
    [string]$Slug,
    [string]$Title,
    [bool]$IsTech
  )

  if ($IsTech) {
    $points = @(
      "$Title 는 수집-정규화-탐지-대응 체인의 특정 책임을 맡는 기술 요소입니다.",
      '정상 기준선과 공격 로그를 함께 확보해야 룰 성능을 안정적으로 측정할 수 있습니다.',
      '성능 지표(지연, 실패율, 자원 사용량)와 보안 지표(탐지율, 오탐률)를 함께 관리해야 합니다.',
      '설정 변경은 스테이징 검증 후 제한된 범위에 점진 적용하는 방식이 안전합니다.',
      '설정값, 룰, 근거 로그를 1:1 매핑해 재현성과 추적성을 확보해야 합니다.'
    )
  } else {
    $points = @(
      "$Title 문서는 팀이 동일한 기준으로 의사결정하도록 핵심 용어와 경계를 고정합니다.",
      '입력 조건, 처리 규칙, 출력 결과를 분리해 기록해야 이슈 재현과 원인 분석이 가능합니다.',
      '탐지 정확도와 운영 안정성을 동시에 관리해야 실제 운영 단계에서 품질이 유지됩니다.',
      '역할 분담, 검증 근거, 변경 이력을 남겨야 협업 비용과 인수인계 비용을 줄일 수 있습니다.',
      'KPI와 회고 결과를 룰/설정 개선으로 연결하는 반복 루프가 필요합니다.'
    )
  }

  switch ($Slug) {
    'logstash' {
      $points[0] = 'Logstash는 비정형 로그를 구조화 필드로 변환하는 ETL 핵심 계층입니다.'
      $points[1] = 'grok/dissect/date/mutate 파이프라인 설계 품질이 전체 탐지 정확도를 좌우합니다.'
    }
    'filebeat-syslog' {
      $points[0] = 'Filebeat/Syslog는 원천 로그를 누락 없이 중앙 파이프라인으로 전달하는 수집 계층입니다.'
      $points[1] = '백프레셔, 네트워크 단절, 재전송 정책을 고려해 유실 위험을 낮춰야 합니다.'
    }
    'elasticsearch' {
      $points[0] = 'Elasticsearch는 대량 보안 이벤트를 색인하고 빠르게 조회하는 저장/검색 계층입니다.'
      $points[1] = '인덱스 템플릿과 매핑 불일치는 검색 실패와 분석 왜곡의 주요 원인입니다.'
    }
    'kibana' {
      $points[0] = 'Kibana는 탐지 결과를 시각화하고 분석/리포팅/검증을 수행하는 운영 인터페이스입니다.'
      $points[1] = '대시보드 구성만으로는 부족하며 경보 검증과 대응 기준까지 함께 정의해야 합니다.'
    }
    'suricata' {
      $points[0] = 'Suricata는 네트워크 트래픽 기반 공격 징후를 탐지/차단하는 NIDS/IPS 엔진입니다.'
      $points[1] = '룰 셋 우선순위, SID 체계, 오탐 제어 정책을 운영 문서와 함께 관리해야 합니다.'
    }
    'modsecurity' {
      $points[0] = 'ModSecurity는 HTTP 요청/응답을 검사해 웹 공격을 탐지·차단하는 WAF 엔진입니다.'
      $points[1] = 'DetectionOnly 단계에서 튜닝 후 차단 모드로 전환해야 서비스 영향도를 낮출 수 있습니다.'
    }
    'wazuh-auditd' {
      $points[0] = 'Wazuh + Auditd는 호스트 행위/시스템 이벤트를 수집해 이상 징후를 분석하는 HIDS 구성입니다.'
      $points[1] = '감사 규칙 범위와 알림 수준을 분리 설계해야 소음 없이 의미 있는 경보를 유지할 수 있습니다.'
    }
    'ansible' {
      $points[0] = 'Ansible은 반복 보안 설정을 코드화해 일관성 있게 반영하는 자동화 오케스트레이션 계층입니다.'
      $points[1] = 'idempotent한 태스크 설계와 dry-run 검증이 운영 안정성의 핵심입니다.'
    }
    'pfsense' {
      $points[0] = 'pfSense는 경계 네트워크 정책을 중앙 통제하는 방화벽/라우팅 게이트웨이입니다.'
      $points[1] = '정책 충돌, NAT/라우팅 우선순위, 롤백 절차를 함께 설계해야 장애를 예방할 수 있습니다.'
    }
    'kpi' {
      $points[0] = 'KPI는 탐지/대응 품질을 수치로 관리해 개선 우선순위를 정하는 기준 체계입니다.'
      $points[1] = 'MTTD, MTTR, 오탐률, 수집성공률을 동시에 추적해야 운영 상태를 균형 있게 볼 수 있습니다.'
    }
    'rule-design' {
      $points[0] = '룰 설계는 근거 로그와 공격 행위를 연결해 탐지 조건을 정의하는 핵심 설계 활동입니다.'
      $points[1] = '탐지 룰과 대응 정책을 분리해 오탐 상황에서도 안전하게 운영 가능하도록 구성해야 합니다.'
    }
    'runbook' {
      $points[0] = 'Runbook은 반복 운영 절차를 체크리스트화해 팀 간 품질 편차를 줄이는 운영 기준 문서입니다.'
      $points[1] = '탐지부터 보고까지의 담당자, 입력값, 승인 조건을 고정해 처리 시간을 단축합니다.'
    }
    'troubleshooting' {
      $points[0] = '트러블슈팅 문서는 증상-원인-점검-조치-재발방지 흐름으로 이슈 대응 지식을 표준화합니다.'
      $points[1] = '재현 가능한 로그와 설정 상태를 남겨야 같은 오류를 빠르게 복구할 수 있습니다.'
    }
  }

  return $points
}

function Get-FlowRows {
  param(
    [string]$Slug,
    [bool]$IsTech
  )

  if ($IsTech) {
    return @(
      [PSCustomObject]@{ step = '수집'; detail = '입력 채널, 포트, 프로토콜, 인증 조건을 점검합니다.'; output = '원천 이벤트 유입 확인' },
      [PSCustomObject]@{ step = '정규화'; detail = '필드 매핑, 타임스탬프 정렬, 스키마 표준화를 적용합니다.'; output = '분석 가능한 표준 이벤트' },
      [PSCustomObject]@{ step = '탐지'; detail = '룰/쿼리/정책으로 이상 행위를 식별하고 우선순위를 분류합니다.'; output = '경보 후보와 증적 데이터' },
      [PSCustomObject]@{ step = '대응'; detail = '자동/수동 대응 플레이북을 적용해 차단·격리·통보를 수행합니다.'; output = '처리 상태 및 영향도 기록' },
      [PSCustomObject]@{ step = '회고'; detail = '오탐/미탐과 처리 지연 원인을 분석해 설정을 개선합니다.'; output = '다음 배포 개선 항목' }
    )
  }

  return @(
    [PSCustomObject]@{ step = '기획'; detail = '목표, 범위, 성공 기준, 제외 범위를 문서화합니다.'; output = '합의된 요구사항' },
    [PSCustomObject]@{ step = '설계'; detail = '아키텍처 흐름, 책임 분담, 데이터 표준을 정의합니다.'; output = '설계 기준서' },
    [PSCustomObject]@{ step = '구현'; detail = '수집-정규화-탐지-대응 체인을 구현하고 연동합니다.'; output = '동작 가능한 파이프라인' },
    [PSCustomObject]@{ step = '검증'; detail = '정상/공격 시나리오를 재현해 탐지·대응 결과를 기록합니다.'; output = '검증 로그와 증적' },
    [PSCustomObject]@{ step = '운영'; detail = 'KPI, Runbook, 회고 루프로 개선을 반복합니다.'; output = '지속 개선 계획' }
  )
}

function Get-ImplementationSteps {
  param(
    [string]$Slug,
    [string]$Title
  )

  $steps = @(
    "$Title 적용 목적과 측정 지표를 먼저 확정합니다.",
    '입력 데이터 형태와 의존 구성요소를 체크리스트로 정리합니다.',
    '정상 동작 기준을 먼저 검증한 뒤 공격/예외 시나리오를 확장합니다.',
    '변경 전후 로그를 비교해 품질 지표 변화를 수치로 기록합니다.',
    '룰/설정 파일과 운영 문서를 동기화하고 변경 이력을 남깁니다.',
    '소규모 적용 후 범위를 확대하는 단계적 배포 전략을 사용합니다.'
  )

  switch ($Slug) {
    'logstash' { $steps[2] = 'grok/dissect/date/mutate를 분리 검증해 파싱 실패 지점을 빠르게 식별합니다.' }
    'suricata' { $steps[2] = '기본 룰셋과 커스텀 룰을 분리 관리하고 SID 충돌 여부를 먼저 점검합니다.' }
    'modsecurity' { $steps[2] = 'DetectionOnly 모드에서 오탐을 조정한 뒤 차단 모드로 점진 전환합니다.' }
    'wazuh-auditd' { $steps[2] = 'Auditd 수집 범위와 Wazuh 경보 레벨을 분리해 경보 소음을 제어합니다.' }
    'ansible' { $steps[2] = 'playbook을 idempotent하게 작성하고 체크 모드로 변경 영향을 사전 검증합니다.' }
    'pfsense' { $steps[2] = '백업 생성 후 규칙을 단계 반영하고 네트워크 영향 범위를 즉시 검증합니다.' }
    'kpi' { $steps[2] = '각 지표의 산식, 데이터 소스, 측정 주기를 한 문서에 고정합니다.' }
    'runbook' { $steps[2] = '체크 항목별 담당자와 승인 조건을 명시해 실행 일관성을 확보합니다.' }
    'troubleshooting' { $steps[2] = '증상-원인-점검-조치 순서를 고정해 긴급 상황에서도 누락을 방지합니다.' }
  }

  return $steps
}

function Get-Snippet {
  param(
    [string]$Slug,
    [bool]$IsTech
  )

  switch ($Slug) {
    'logstash' { return @'
input { beats { port => 5044 } }
filter {
  grok { match => { "message" => "%{COMBINEDAPACHELOG}" } }
  date { match => ["timestamp", "dd/MMM/yyyy:HH:mm:ss Z"] }
}
output { elasticsearch { hosts => ["http://localhost:9200"] } }
'@ }
    'filebeat-syslog' { return @'
filebeat.inputs:
  - type: log
    paths:
      - /var/log/auth.log
      - /var/log/nginx/access.log
output.logstash:
  hosts: ["10.10.0.10:5044"]
'@ }
    'elasticsearch' { return @'
PUT _index_template/purple-logs
{
  "index_patterns": ["purple-*"],
  "template": {
    "mappings": {
      "properties": {
        "source.ip": { "type": "ip" },
        "@timestamp": { "type": "date" }
      }
    }
  }
}
'@ }
    'kibana' { return @'
event.module : "wazuh" and rule.level >= 10 and not source.ip : "10.10.0.0/16"
'@ }
    'suricata' { return @'
alert http any any -> any any (
  msg:"WEB Directory Traversal";
  content:"../"; http_uri;
  sid:1002001; rev:2;
)
'@ }
    'modsecurity' { return @'
SecRule REQUEST_URI|ARGS "@rx \.\./" \
 "id:1003001,phase:2,log,deny,msg:'Traversal Attempt',severity:'CRITICAL'"
'@ }
    'wazuh-auditd' { return @'
<rule id="100203" level="8">
  <if_sid>5710</if_sid>
  <match>nessus</match>
  <description>Scanner signature detected on host</description>
</rule>
'@ }
    'ansible' { return @'
- hosts: firewall
  tasks:
    - name: Block suspicious source
      ansible.builtin.command: "iptables -I INPUT -s {{ src_ip }} -j DROP"
'@ }
    'pfsense' { return @'
cp /cf/conf/config.xml /cf/conf/config.xml.bak.$(date +%Y%m%d%H%M%S)
pfSsh.php playback configreload
pfctl -sr
'@ }
    'nessus' { return @'
# Nessus 결과 연동 절차
1) 고위험 취약점과 증적 로그를 연결
2) 탐지 룰 초안을 생성
3) 공격 재현으로 룰 탐지 여부 확인
'@ }
    'cape' { return @'
tail -f /opt/CAPEv2/log/cuckoo.log
python3 utils/process.py --task-id 1024
'@ }
    'gns3-network' { return @'
show ip route
show frame-relay map
ping 10.10.20.2 source 10.10.20.1
'@ }
    'kpi' { return @'
MTTD = 탐지시각 - 공격발생시각
MTTR = 대응완료시각 - 탐지시각
오탐률 = 오탐경보 / 전체경보
수집성공률 = 수집이벤트 / 발생이벤트
'@ }
    default {
      if ($IsTech) {
        return @'
# 운영 검증 예시
1) 입력 경로 점검
2) 정상/공격 로그 비교
3) 대응 정책 적용 결과 기록
'@
      }

      return @'
# 문서 실행 예시
1) 범위와 목표 확인
2) 단계별 점검 수행
3) 결과를 KPI와 회고에 반영
'@
    }
  }
}

function Get-ValidationRows {
  param([string]$Slug)

  if ($Slug -eq 'kpi') {
    return @(
      [PSCustomObject]@{ metric = 'MTTD'; target = '5분 이내'; method = '공격 시각과 탐지 시각 차이 측정' },
      [PSCustomObject]@{ metric = 'MTTR'; target = '15분 이내'; method = '탐지 후 대응 완료까지 시간 측정' },
      [PSCustomObject]@{ metric = '오탐률'; target = '10% 이하'; method = '경보 샘플 검토 및 오탐 비율 계산' },
      [PSCustomObject]@{ metric = '수집성공률'; target = '99% 이상'; method = '발생 이벤트 대비 수집 이벤트 비교' }
    )
  }

  return @(
    [PSCustomObject]@{ metric = '정확도'; target = '90% 이상'; method = '공격 시나리오 재현 시 탐지 성공률 측정' },
    [PSCustomObject]@{ metric = '지연'; target = '서비스 기준 이내'; method = '이벤트 유입부터 경보 발생까지 시간 측정' },
    [PSCustomObject]@{ metric = '안정성'; target = '재시작 없이 운영'; method = '오류 로그/재기동 횟수 주간 점검' },
    [PSCustomObject]@{ metric = '운영성'; target = '문서와 실행 일치'; method = 'Runbook 항목과 실제 수행 로그 대조' }
  )
}

function Get-OpsChecklist {
  param([string]$Title)
  return @(
    "$Title 적용 전 권한, 포트, 의존 서비스 상태를 확인한다.",
    '입력/출력 로그가 모두 수집되는지 샘플 이벤트로 검증한다.',
    '정상 트래픽과 공격 트래픽을 분리해 결과를 비교한다.',
    '오탐/미탐 사례를 별도 기록하고 룰 개선 항목을 추출한다.',
    '변경 이력(무엇, 왜, 언제, 담당자)을 문서에 남긴다.',
    'Runbook 기준으로 실제 운영 절차를 점검한다.'
  )
}

function Get-TroubleRows {
  return @(
    [PSCustomObject]@{ symptom = '이벤트가 보이지 않음'; cause = '수집 경로/포트/권한 문제'; check = '에이전트 상태, 네트워크 연결, 입력 설정 점검'; action = '수집 경로 복구 후 샘플 로그 재검증' },
    [PSCustomObject]@{ symptom = '경보가 과도하게 발생'; cause = '조건 과민 또는 기준선 부재'; check = '오탐 로그 샘플링 및 조건 비교'; action = '예외 조건 보강 및 임계치 조정' },
    [PSCustomObject]@{ symptom = '탐지가 누락됨'; cause = '필드 매핑 불일치, 룰 범위 누락'; check = '원문 로그와 탐지 조건 필드 매핑 대조'; action = '필드 정규화 보완 및 룰 조건 수정' },
    [PSCustomObject]@{ symptom = '대응 지연 발생'; cause = '역할/승인 절차 불명확'; check = 'Runbook 단계별 소요 시간 확인'; action = '승인 체계 단순화 및 자동화 대상 분리' }
  )
}

function Get-FaqRows {
  param(
    [string]$Title,
    [bool]$IsTech
  )

  if ($IsTech) {
    return @(
      [PSCustomObject]@{ q = '이 요소를 먼저 튜닝해야 하는 신호는 무엇인가?'; a = '오탐 증가, 지연 급등, 파싱 실패율 상승이 동시에 보이면 우선 점검합니다.' },
      [PSCustomObject]@{ q = '운영 중 변경은 언제 반영해야 하는가?'; a = '증적 로그와 영향 범위를 확보한 뒤 유지보수 시간대에 단계적으로 반영합니다.' },
      [PSCustomObject]@{ q = '오탐을 줄이면서 미탐을 늘리지 않으려면?'; a = '예외 조건은 좁게 추가하고 반드시 공격 재현 테스트를 함께 수행합니다.' },
      [PSCustomObject]@{ q = '문서 업데이트 주기는?'; a = '룰/설정 변경 즉시 업데이트하고 주간 회고에서 누락 여부를 점검합니다.' }
    )
  }

  return @(
    [PSCustomObject]@{ q = "$Title 문서는 누가 관리하는가?"; a = '해당 섹션 책임자가 초안 유지, 팀 리뷰로 확정하는 방식이 권장됩니다.' },
    [PSCustomObject]@{ q = '어느 수준까지 상세화해야 하는가?'; a = '신규 팀원이 문서만으로 동일 결과를 재현할 수 있는 수준까지 상세화합니다.' },
    [PSCustomObject]@{ q = '검증 증적은 무엇을 남겨야 하는가?'; a = '원문 로그, 탐지 결과, 대응 실행 로그, 변경 diff를 함께 남깁니다.' },
    [PSCustomObject]@{ q = '문서가 실제와 달라졌을 때 우선순위는?'; a = '실제 운영 절차를 먼저 복구하고 즉시 문서를 갱신해 불일치를 제거합니다.' }
  )
}

function Get-DefaultRelatedLinks {
  param(
    [bool]$IsTech
  )

  if ($IsTech) {
    return @(
      [PSCustomObject]@{ href = '../overview.html'; text = '프로젝트 개요' },
      [PSCustomObject]@{ href = '../rule-design.html'; text = '룰 설계 가이드' },
      [PSCustomObject]@{ href = '../troubleshooting.html'; text = '트러블슈팅' }
    )
  }

  return @(
    [PSCustomObject]@{ href = 'overview.html'; text = '프로젝트 개요' },
    [PSCustomObject]@{ href = 'architecture-flow.html'; text = '전체 아키텍처 흐름' },
    [PSCustomObject]@{ href = 'references.html'; text = '관련 문서' }
  )
}

function Build-ListHtml {
  param([object[]]$Items)
  return (($Items | ForEach-Object { "<li>$(Escape-Html $_)</li>" }) -join "`n")
}

function Build-RelatedHtml {
  param([object[]]$Items)
  return (($Items | ForEach-Object {
      "<li><a href=""$(Escape-Html $_.href)"">$(Escape-Html $_.text)</a></li>"
    }) -join "`n")
}

function Build-ThreeColTableRows {
  param([object[]]$Rows)
  return (($Rows | ForEach-Object {
      "<tr><td>$(Escape-Html $_.step)</td><td>$(Escape-Html $_.detail)</td><td>$(Escape-Html $_.output)</td></tr>"
    }) -join "`n")
}

function Build-ValidationRows {
  param([object[]]$Rows)
  return (($Rows | ForEach-Object {
      "<tr><td>$(Escape-Html $_.metric)</td><td>$(Escape-Html $_.target)</td><td>$(Escape-Html $_.method)</td></tr>"
    }) -join "`n")
}

function Build-TroubleRows {
  param([object[]]$Rows)
  return (($Rows | ForEach-Object {
      "<tr><td>$(Escape-Html $_.symptom)</td><td>$(Escape-Html $_.cause)</td><td>$(Escape-Html $_.check)</td><td>$(Escape-Html $_.action)</td></tr>"
    }) -join "`n")
}

function Build-FaqRows {
  param([object[]]$Rows)
  return (($Rows | ForEach-Object {
      "<tr><th>$(Escape-Html $_.q)</th><td>$(Escape-Html $_.a)</td></tr>"
    }) -join "`n")
}

$files = Get-ChildItem -Path $docsRoot -Recurse -File -Filter '*.html'

$updated = 0
$wikiPages = @()

foreach ($file in $files) {
  $raw = Get-Content -Path $file.FullName -Raw
  $title = Get-H1Text -Raw $raw
  if ([string]::IsNullOrWhiteSpace($title)) { continue }

  $summary = Get-TagInnerText -Raw $raw -Tag 'div' -ClassName 'doc-summary'
  if ([string]::IsNullOrWhiteSpace($summary)) {
    $summary = Get-TagInnerText -Raw $raw -Tag 'p' -ClassName 'article-desc'
  }
  if ([string]::IsNullOrWhiteSpace($summary)) {
    $summary = "$title 문서의 핵심 개념과 운영 기준을 정리합니다."
  }

  $isTech = $file.DirectoryName -like "*\docs\tech"
  $slug = [System.IO.Path]::GetFileNameWithoutExtension($file.Name).ToLowerInvariant()

  $related = Get-RelatedLinks -Raw $raw
  if ($related.Count -eq 0) {
    $related = Get-DefaultRelatedLinks -IsTech $isTech
  }

  $conceptPoints = Get-ConceptPoints -Slug $slug -Title $title -IsTech $isTech
  $flowRows = Get-FlowRows -Slug $slug -IsTech $isTech
  $implementationSteps = Get-ImplementationSteps -Slug $slug -Title $title
  $snippet = Get-Snippet -Slug $slug -IsTech $isTech
  $validationRows = Get-ValidationRows -Slug $slug
  $opsChecklist = Get-OpsChecklist -Title $title
  $troubleRows = Get-TroubleRows
  $faqRows = Get-FaqRows -Title $title -IsTech $isTech

  $conceptHtml = Build-ListHtml -Items $conceptPoints
  $flowRowsHtml = Build-ThreeColTableRows -Rows $flowRows
  $implementationHtml = Build-ListHtml -Items $implementationSteps
  $validationHtml = Build-ValidationRows -Rows $validationRows
  $opsHtml = Build-ListHtml -Items $opsChecklist
  $troubleHtml = Build-TroubleRows -Rows $troubleRows
  $faqHtml = Build-FaqRows -Rows $faqRows
  $relatedHtml = Build-RelatedHtml -Items $related

  $escapedTitle = Escape-Html $title
  $escapedSummary = Escape-Html $summary
  $escapedSnippet = Escape-Html $snippet

  $rootPrefix = if ($isTech) { '../../' } else { '../' }
  $homeHref = "${rootPrefix}index.html"
  $hubHref = "${rootPrefix}docs/tech-index.html"
  $assetHref = "${rootPrefix}article-asset-index.html"
  $helpHref = "${rootPrefix}docs/glossary.html"
  $cssHref = "${rootPrefix}wiki.css"
  $pagesJsSrc = "${rootPrefix}wiki-pages.js"
  $uiJsSrc = "${rootPrefix}wiki-ui.js"

  $docPath = if ($isTech) { '퍼플위키 / 요소 문서 / 기술' } else { '퍼플위키 / 요소 문서 / 섹션' }
  $docType = if ($isTech) { '기술 요소' } else { '섹션 문서' }
  $relatedCount = $related.Count

  $hrefFromRoot = $file.FullName.Substring($PSScriptRoot.Length + 1) -replace '\\', '/'
  $wikiPages += [PSCustomObject]@{
    title = $title
    href = $hrefFromRoot
    summary = $summary
  }

  $html = @"
<!doctype html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>퍼플위키 - $escapedTitle</title>
  <link rel="stylesheet" href="$cssHref" />
</head>
<body>
  <header class="wiki-topbar">
    <div class="top-inner">
      <a class="brand" href="$homeHref" aria-label="퍼플위키 홈">
        <span class="brand-mark">P</span>
        <strong>퍼플위키</strong>
      </a>
      <nav class="top-nav">
        <a href="$homeHref">개념 문서</a>
        <a class="active" href="$hubHref">요소 허브</a>
        <a href="$assetHref">자료 인덱스</a>
      </nav>
      <div class="top-right">
        <div class="global-search" role="search" aria-label="퍼플위키 검색">
          <input id="global-search-input" type="search" placeholder="퍼플위키 검색" />
          <div id="global-search-suggest" class="search-suggest" hidden></div>
        </div>
        <div class="top-note">
          <a id="random-page-link" href="#">랜덤</a> · <a href="$helpHref">도움말</a>
        </div>
      </div>
    </div>
  </header>

  <section class="article-title">
    <div class="title-main">
      <p class="article-path">$docPath</p>
      <h1>$escapedTitle</h1>
      <div class="article-lastmod">최근 수정 시각: $now</div>
      <div class="article-tabs">
        <a class="active" href="#">읽기</a>
        <a href="$hubHref">요소</a>
        <a href="$assetHref">자료</a>
        <a href="$homeHref">메인</a>
      </div>
      <p class="article-desc">$escapedSummary</p>
    </div>
    <aside class="info-box">
      <h2>문서 요약</h2>
      <div class="info-list">
        <div><span>문서 유형</span><strong>$docType</strong></div>
        <div><span>섹션 수</span><strong>10개</strong></div>
        <div><span>연관 문서</span><strong>$($relatedCount)개</strong></div>
        <div><span>바로가기</span><strong><a href="$hubHref">요소 허브</a></strong></div>
      </div>
    </aside>
  </section>

  <section class="wiki-tools">
    <div class="tool-tabs" role="tablist" aria-label="문서 탭">
      <button type="button" class="tab active" data-mode="read">읽기</button>
      <button type="button" class="tab" data-mode="fold">문단 관리</button>
      <button type="button" class="tab" data-mode="nav">탐색</button>
    </div>
    <div class="tool-actions">
      <input id="page-search-input" type="search" placeholder="문서 내 검색" />
      <button id="expand-all-btn" type="button">전체 펼치기</button>
      <button id="collapse-all-btn" type="button">전체 접기</button>
      <button id="clear-search-btn" type="button">검색 초기화</button>
      <span id="search-result-text" class="search-result-text">검색 대기 중</span>
    </div>
  </section>

  <main class="layout">
    <section class="content">
      <section id="outline" class="panel">
        <h2>1. 개요</h2>
        <p>$escapedSummary</p>
      </section>

      <section id="concept-deep" class="panel">
        <h2>2. 핵심 개념 심화</h2>
        <ol class="ordered">
$conceptHtml
        </ol>
      </section>

      <section id="flow-model" class="panel">
        <h2>3. 구성 흐름</h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>단계</th>
                <th>설명</th>
                <th>결과물</th>
              </tr>
            </thead>
            <tbody>
$flowRowsHtml
            </tbody>
          </table>
        </div>
      </section>

      <section id="implementation" class="panel">
        <h2>4. 구현 절차</h2>
        <ol class="ordered">
$implementationHtml
        </ol>
      </section>

      <section id="examples" class="panel">
        <h2>5. 로그/설정 예시</h2>
        <pre><code>$escapedSnippet</code></pre>
      </section>

      <section id="validation" class="panel">
        <h2>6. 검증 기준</h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>지표</th>
                <th>목표</th>
                <th>측정 방법</th>
              </tr>
            </thead>
            <tbody>
$validationHtml
            </tbody>
          </table>
        </div>
      </section>

      <section id="ops-checklist" class="panel">
        <h2>7. 운영 체크리스트</h2>
        <ol class="ordered">
$opsHtml
        </ol>
      </section>

      <section id="troubleshooting" class="panel">
        <h2>8. 트러블슈팅</h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>증상</th>
                <th>원인</th>
                <th>점검</th>
                <th>조치</th>
              </tr>
            </thead>
            <tbody>
$troubleHtml
            </tbody>
          </table>
        </div>
      </section>

      <section id="faq" class="panel">
        <h2>9. FAQ</h2>
        <div class="table-wrap">
          <table>
            <tbody>
$faqHtml
            </tbody>
          </table>
        </div>
      </section>

      <section id="related" class="panel">
        <h2>10. 연관 문서</h2>
        <ol class="ordered">
$relatedHtml
        </ol>
      </section>
    </section>

    <aside class="toc">
      <h2>목차</h2>
      <div class="toc-tools">
        <button id="toc-collapse-btn" type="button">목차 접기</button>
      </div>
      <a href="#outline">1. 개요</a>
      <a href="#concept-deep">2. 핵심 개념 심화</a>
      <a href="#flow-model">3. 구성 흐름</a>
      <a href="#implementation">4. 구현 절차</a>
      <a href="#examples">5. 로그/설정 예시</a>
      <a href="#validation">6. 검증 기준</a>
      <a href="#ops-checklist">7. 운영 체크리스트</a>
      <a href="#troubleshooting">8. 트러블슈팅</a>
      <a href="#faq">9. FAQ</a>
      <a href="#related">10. 연관 문서</a>
    </aside>
  </main>

  <div class="category-box">
    <strong>분류</strong>
    <a href="$homeHref">퍼플위키</a>
    <a href="$hubHref">$docType</a>
    <a href="#related">연관 문서</a>
  </div>
  <footer class="license-box">
    이 문서는 퍼플팀 내부 학습 및 프로젝트 정리를 위한 문서입니다.
  </footer>

  <button id="back-to-top-btn" class="back-to-top-btn" type="button" aria-label="맨 위로">▲</button>
  <script src="$pagesJsSrc"></script>
  <script src="$uiJsSrc"></script>
</body>
</html>
"@

  Set-Content -Path $file.FullName -Value $html -Encoding UTF8
  $updated += 1
}

$pagesAll = @(
  [PSCustomObject]@{ title = '3차 퍼플팀 프로젝트 개념 총정리'; href = 'index.html'; summary = '프로젝트 전체 흐름과 기술/운영 개념을 한 문서로 정리합니다.' },
  [PSCustomObject]@{ title = '퍼플위키: 프로젝트 자료 인덱스'; href = 'article-asset-index.html'; summary = '저장소 파일/폴더/링크/통계를 탐색합니다.' }
) + $wikiPages

$pagesAll = $pagesAll | Sort-Object title
$json = $pagesAll | ConvertTo-Json -Depth 4
$js = @"
(() => {
  const currentScript = document.currentScript;
  try {
    window.WIKI_BASE_URL = currentScript ? new URL('.', currentScript.src).href : new URL('.', window.location.href).href;
  } catch (_) {
    window.WIKI_BASE_URL = new URL('.', window.location.href).href;
  }
  window.WIKI_PAGES = $json;
})();
"@

Set-Content -Path (Join-Path $PSScriptRoot 'wiki-pages.js') -Value $js -Encoding UTF8

Write-Output "Updated docs: $updated"



