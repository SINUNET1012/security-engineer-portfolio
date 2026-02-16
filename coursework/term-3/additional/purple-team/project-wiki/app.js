(() => {
  const data = window.WIKI_DATA;
  if (!data || !Array.isArray(data.files)) {
    document.body.insertAdjacentHTML("afterbegin", "<p>데이터 로딩에 실패했습니다.</p>");
    return;
  }

  const files = data.files.map((item) => {
    const modifiedIso = item.modified.replace(" ", "T");
    return {
      ...item,
      modifiedDate: new Date(modifiedIso),
    };
  });

  const numberFmt = new Intl.NumberFormat("ko-KR");

  const knownTopFolders = [
    "00_개인 폴더",
    "01_프로젝트 관리",
    "02_학습자료",
    "03_메뉴얼, 룰셋",
    "04_발표자료",
    "99_회의록",
    "통합 기술리스트.xlsx",
  ];

  const folderRemark = {
    "00_개인 폴더": "팀원별 개인 실습 자료, 가상머신/압축 파일, 상세 로그",
    "01_프로젝트 관리": "현재 파일 없음(빈 폴더)",
    "02_학습자료": "예복습 문서, 흐름 정리 문서, 패킷/참고 링크",
    "03_메뉴얼, 룰셋": "구축 메뉴얼, Nessus 기반 탐지 룰셋 정리",
    "04_발표자료": "발표용 이미지/실행 파일",
    "99_회의록": "일정/역할 분배/작업 공유 회의 기록",
    "통합 기술리스트.xlsx": "기술 학습 범위 기준 문서",
  };

  const timeline = [
    {
      date: "2026-01-17",
      title: "기술리스트 전략 회의",
      body: "깊이 중심 학습 vs 범위 중심 학습 방향을 논의하고, 프로젝트 목표 기반 기술 선정 원칙을 정함.",
    },
    {
      date: "2026-01-21",
      title: "3차 구현 방향 합의",
      body: "로그 수집/가공/시각화/자동화 흐름(시그니처 -> 룰셋 -> Kibana -> 자동 대응)을 공통 프레임으로 정리.",
    },
    {
      date: "2026-01-26",
      title: "본격 일정 시작",
      body: "프로젝트 마감 역산 일정 확정. 자동화 핵심 목표를 \"로그 수집 -> 분석 -> 자동 대응\"으로 명시.",
    },
    {
      date: "2026-02-01",
      title: "SOC 스택 점검",
      body: "ModSecurity/Suricata 공유, ELK 파이프라인 점검, Wazuh/Winbeat/Syslog/DB 연동 과제 도출.",
    },
    {
      date: "2026-02-08",
      title: "룰 보강/연계성 검토",
      body: "Wazuh-Audit 연계, ModSecurity Nessus 룰 보완, Suricata SID 정리 필요사항 확인.",
    },
    {
      date: "2026-02-10",
      title: "공유/인수인계 단계",
      body: "Ansible 기반 구축 자동화 완료 후, 팀원 전원의 개념 이해도 상향과 매뉴얼 통합 정리를 목표로 전환.",
    },
  ];

  const heroMeta = document.getElementById("hero-meta");
  const uniqueTopCount = new Set(files.map((f) => f.topFolder)).size;
  const extTop = [...data.summary.byExtension].sort((a, b) => b.count - a.count)[0];
  const sizeGb = data.summary.totalSizeMB / 1024;

  heroMeta.innerHTML = [
    { label: "총 파일", value: `${numberFmt.format(data.summary.totalFiles)}개` },
    { label: "총 용량", value: `${sizeGb.toFixed(2)} GB` },
    { label: "상위 폴더", value: `${numberFmt.format(uniqueTopCount)}개` },
    { label: "생성 시각", value: data.generatedAt },
    { label: "최다 확장자", value: `${extTop.ext} (${numberFmt.format(extTop.count)}개)` },
    { label: "외부 링크", value: `${numberFmt.format(data.links.length)}개` },
  ]
    .map(
      (meta) => `
      <div class="meta-item">
        <span>${escapeHtml(meta.label)}</span>
        <strong>${escapeHtml(meta.value)}</strong>
      </div>
    `
    )
    .join("");

  renderStats();
  renderTimeline();
  renderFolderTable();
  renderMemberTable();
  renderTopFiles();
  renderLinks();
  setupFileIndex();

  function renderStats() {
    const statGrid = document.getElementById("stat-grid");
    const meetingFiles = files.filter((f) => f.topFolder === "99_회의록").length;
    const manualFiles = files.filter((f) => f.topFolder === "03_메뉴얼, 룰셋").length;
    const personalFiles = files.filter((f) => f.topFolder === "00_개인 폴더").length;

    const cards = [
      { label: "회의록 문서", value: `${numberFmt.format(meetingFiles)}개` },
      { label: "메뉴얼/룰셋", value: `${numberFmt.format(manualFiles)}개` },
      { label: "개인 폴더 자산", value: `${numberFmt.format(personalFiles)}개` },
      { label: "확장자 종류", value: `${numberFmt.format(data.summary.byExtension.length)}종` },
      { label: "프로젝트 관리 폴더", value: "현재 비어 있음" },
      { label: "핵심 키워드", value: "ELK / Wazuh / Suricata / ModSecurity / Ansible" },
    ];

    statGrid.innerHTML = cards
      .map(
        (c) => `
      <article class="stat-card">
        <span>${escapeHtml(c.label)}</span>
        <strong>${escapeHtml(c.value)}</strong>
      </article>
    `
      )
      .join("");
  }

  function renderTimeline() {
    const container = document.getElementById("timeline-list");
    container.innerHTML = timeline
      .map(
        (item) => `
      <article class="timeline-item">
        <div class="date">${escapeHtml(item.date)}</div>
        <div class="title">${escapeHtml(item.title)}</div>
        <div>${escapeHtml(item.body)}</div>
      </article>
    `
      )
      .join("");
  }

  function renderFolderTable() {
    const box = document.getElementById("folder-table");
    const map = new Map(data.summary.byTopFolder.map((x) => [x.topFolder, x]));

    const rows = knownTopFolders.map((name) => {
      const rec = map.get(name);
      const count = rec ? rec.fileCount : 0;
      const size = rec ? rec.totalSizeMB : 0;
      return {
        folder: name,
        fileCount: count,
        sizeMB: size,
        remark: folderRemark[name] || "",
      };
    });

    box.innerHTML = buildTable(
      ["폴더", "파일 수", "용량", "설명"],
      rows.map((r) => [
        escapeHtml(r.folder),
        `${numberFmt.format(r.fileCount)}개`,
        formatMB(r.sizeMB),
        escapeHtml(r.remark),
      ])
    );
  }

  function renderMemberTable() {
    const box = document.getElementById("member-table");
    const memberMap = new Map();

    files
      .filter((f) => f.path.startsWith("00_개인 폴더/"))
      .forEach((f) => {
        const seg = f.path.split("/");
        const member = seg.length >= 3 ? seg[1] : "공용";
        if (!memberMap.has(member)) {
          memberMap.set(member, {
            name: member,
            count: 0,
            sizeMB: 0,
            tags: new Set(),
          });
        }

        const item = memberMap.get(member);
        item.count += 1;
        item.sizeMB += f.sizeMB;

        const lower = f.path.toLowerCase();
        if (lower.includes("cape")) item.tags.add("CAPE");
        if (lower.includes("ospf") || lower.includes("eigrp") || lower.includes("rip") || lower.includes("ipv6")) item.tags.add("네트워크");
        if (lower.includes("nessus") || lower.includes("wazuh") || lower.includes("suricata") || lower.includes("modsecurity")) item.tags.add("보안탐지");
        if (lower.includes("vm") || lower.includes("vmdk") || lower.includes("zip")) item.tags.add("가상환경");
        if (f.ext === ".txt") item.tags.add("실행로그");
      });

    const rows = [...memberMap.values()].sort((a, b) => a.name.localeCompare(b.name, "ko"));
    box.innerHTML = buildTable(
      ["팀원/구분", "파일 수", "용량", "주요 성격"],
      rows.map((r) => [
        escapeHtml(r.name),
        `${numberFmt.format(r.count)}개`,
        formatMB(r.sizeMB),
        escapeHtml([...r.tags].join(", ") || "-"),
      ])
    );
  }

  function renderTopFiles() {
    const box = document.getElementById("top-file-table");
    const top = [...files].sort((a, b) => b.sizeBytes - a.sizeBytes).slice(0, 12);

    box.innerHTML = buildTable(
      ["순위", "경로", "크기", "수정일"],
      top.map((f, i) => [
        `${i + 1}`,
        `<span class="path-cell">${escapeHtml(f.path)}</span>`,
        formatMB(f.sizeMB),
        escapeHtml(f.modified),
      ])
    );
  }

  function renderLinks() {
    const container = document.getElementById("link-list");
    if (!data.links.length) {
      container.innerHTML = "<p>링크 데이터가 없습니다.</p>";
      return;
    }

    container.innerHTML = data.links
      .map(
        (item) => `
      <article class="link-item">
        <strong>${escapeHtml(item.title)}</strong>
        <div><code>${escapeHtml(item.path)}</code></div>
        <a href="${escapeHtml(item.url)}" target="_blank" rel="noreferrer noopener">${escapeHtml(item.url)}</a>
      </article>
    `
      )
      .join("");
  }

  function setupFileIndex() {
    const folderFilter = document.getElementById("folder-filter");
    const extFilter = document.getElementById("ext-filter");
    const searchInput = document.getElementById("search-input");
    const sortSelect = document.getElementById("sort-select");
    const resetBtn = document.getElementById("reset-btn");
    const fileTable = document.getElementById("file-table");
    const resultMeta = document.getElementById("result-meta");

    const folderOptions = ["(전체)", ...knownTopFolders];
    folderFilter.innerHTML = folderOptions
      .map((name) => `<option value="${escapeHtml(name)}">폴더: ${escapeHtml(name)}</option>`)
      .join("");

    const extOptions = ["(전체)", ...new Set(files.map((f) => f.ext))].sort((a, b) => a.localeCompare(b));
    extFilter.innerHTML = extOptions
      .map((ext) => `<option value="${escapeHtml(ext)}">확장자: ${escapeHtml(ext)}</option>`)
      .join("");

    const onChange = () => {
      const query = searchInput.value.trim().toLowerCase();
      const folder = folderFilter.value;
      const ext = extFilter.value;
      const sort = sortSelect.value;

      let filtered = files.filter((f) => {
        const qOk = !query || f.path.toLowerCase().includes(query);
        const folderOk = folder === "(전체)" || f.topFolder === folder;
        const extOk = ext === "(전체)" || f.ext === ext;
        return qOk && folderOk && extOk;
      });

      if (sort === "path") {
        filtered = filtered.sort((a, b) => a.path.localeCompare(b.path, "ko"));
      } else if (sort === "size") {
        filtered = filtered.sort((a, b) => b.sizeBytes - a.sizeBytes);
      } else if (sort === "date") {
        filtered = filtered.sort((a, b) => b.modifiedDate - a.modifiedDate);
      }

      resultMeta.textContent = `${numberFmt.format(data.summary.totalFiles)}개 중 ${numberFmt.format(filtered.length)}개 표시`;

      fileTable.innerHTML = buildTable(
        ["경로", "폴더", "확장자", "크기", "수정일", "작업"],
        filtered.map((f) => [
          `<span class="path-cell">${escapeHtml(f.path)}</span>`,
          escapeHtml(f.topFolder),
          escapeHtml(f.ext),
          formatMB(f.sizeMB),
          escapeHtml(f.modified),
          `<button class="copy-btn" type="button" data-path="${escapeAttr(f.path)}">경로 복사</button>`,
        ])
      );
    };

    [folderFilter, extFilter, searchInput, sortSelect].forEach((el) => {
      el.addEventListener("input", onChange);
      el.addEventListener("change", onChange);
    });

    resetBtn.addEventListener("click", () => {
      searchInput.value = "";
      folderFilter.value = "(전체)";
      extFilter.value = "(전체)";
      sortSelect.value = "path";
      onChange();
    });

    fileTable.addEventListener("click", async (event) => {
      const target = event.target;
      if (!(target instanceof HTMLButtonElement)) return;
      if (!target.classList.contains("copy-btn")) return;
      const path = target.dataset.path || "";
      if (!path) return;

      const ok = await copyText(path);
      const prev = target.textContent;
      target.textContent = ok ? "복사됨" : "복사 실패";
      setTimeout(() => {
        target.textContent = prev;
      }, 900);
    });

    onChange();
  }

  function buildTable(headers, rows) {
    return `
      <div class="table-wrap">
        <table>
          <thead>
            <tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr>
          </thead>
          <tbody>
            ${rows.map((row) => `<tr>${row.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  function formatMB(value) {
    if (value >= 1024) return `${(value / 1024).toFixed(2)} GB`;
    if (value < 0.001) return `${(value * 1024).toFixed(2)} KB`;
    return `${value.toFixed(3)} MB`;
  }

  function escapeHtml(str) {
    return String(str)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function escapeAttr(str) {
    return escapeHtml(str);
  }

  async function copyText(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (err) {
      // Fallback below.
    }

    try {
      const temp = document.createElement("textarea");
      temp.value = text;
      document.body.appendChild(temp);
      temp.select();
      const ok = document.execCommand("copy");
      temp.remove();
      return ok;
    } catch (err) {
      return false;
    }
  }
})();
