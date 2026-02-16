(() => {
  const tocLinks = Array.from(document.querySelectorAll('.doc-toc a[href^="#"]'));
  const backToTopBtn = document.getElementById('back-to-top-btn');
  const sections = tocLinks
    .map((link) => {
      const id = decodeURIComponent(link.getAttribute('href').slice(1));
      const section = document.getElementById(id);
      return section ? { id, link, section } : null;
    })
    .filter(Boolean);

  if (!sections.length) {
    bindBackToTop();
    return;
  }

  const sectionMap = new Map(sections.map((item) => [item.id, item.section]));
  const article = document.querySelector('.doc-article');

  let searchInput = null;
  let resultMeta = null;

  attachDocTools();
  attachSectionActions();
  bindSearch();
  bindTocBehavior();
  bindBackToTop();

  function attachDocTools() {
    if (!article) return;

    const firstSection = article.querySelector('.doc-section');
    if (!firstSection) return;

    const tools = document.createElement('div');
    tools.className = 'doc-tools';
    tools.innerHTML = `
      <input id="doc-search-input" type="search" placeholder="문서 내 검색 (/)" />
      <button id="doc-expand-all-btn" type="button">전체 펼치기</button>
      <button id="doc-collapse-all-btn" type="button">전체 접기</button>
      <button id="doc-clear-search-btn" type="button">검색 초기화</button>
      <span id="doc-search-result" class="doc-tools-meta">검색 대기 중</span>
    `;

    article.insertBefore(tools, firstSection);

    searchInput = tools.querySelector('#doc-search-input');
    resultMeta = tools.querySelector('#doc-search-result');

    const expandBtn = tools.querySelector('#doc-expand-all-btn');
    const collapseBtn = tools.querySelector('#doc-collapse-all-btn');
    const clearBtn = tools.querySelector('#doc-clear-search-btn');

    expandBtn?.addEventListener('click', () => {
      sections.forEach((item) => setCollapsed(item.section, false));
    });

    collapseBtn?.addEventListener('click', () => {
      sections.forEach((item) => setCollapsed(item.section, true));
    });

    clearBtn?.addEventListener('click', () => {
      if (!searchInput) return;
      searchInput.value = '';
      runSearch();
      searchInput.focus();
    });
  }

  function attachSectionActions() {
    sections.forEach((item) => {
      const heading = item.section.querySelector(':scope > h2');
      if (!heading) return;

      const headingText = heading.textContent.trim();
      const actions = document.createElement('span');
      actions.className = 'doc-section-actions';

      const toggleBtn = document.createElement('button');
      toggleBtn.type = 'button';
      toggleBtn.dataset.action = 'toggle';
      toggleBtn.textContent = '[접기]';
      toggleBtn.setAttribute('aria-expanded', 'true');
      toggleBtn.setAttribute('aria-label', `${headingText} 접기`);

      const linkBtn = document.createElement('button');
      linkBtn.type = 'button';
      linkBtn.dataset.action = 'link';
      linkBtn.textContent = '[링크]';
      linkBtn.setAttribute('aria-label', `${headingText} 링크 복사`);

      actions.append(toggleBtn, linkBtn);
      heading.append(actions);

      const body = document.createElement('div');
      body.className = 'doc-section-body';
      while (heading.nextSibling) {
        body.appendChild(heading.nextSibling);
      }
      item.section.appendChild(body);

      toggleBtn.addEventListener('click', () => {
        setCollapsed(item.section, !item.section.classList.contains('is-collapsed'));
      });

      linkBtn.addEventListener('click', async () => {
        const url = new URL(`#${item.id}`, window.location.href).href;
        const copied = await copyText(url);
        const prev = linkBtn.textContent;
        linkBtn.textContent = copied ? '[복사됨]' : '[실패]';
        window.setTimeout(() => {
          linkBtn.textContent = prev;
        }, 800);
      });
    });
  }

  function bindSearch() {
    if (!searchInput) return;
    searchInput.addEventListener('input', runSearch);

    window.addEventListener('keydown', (event) => {
      const target = event.target;
      const isTypingElement =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        (target instanceof HTMLElement && target.isContentEditable);

      if (event.key === '/' && !isTypingElement) {
        event.preventDefault();
        searchInput.focus();
      }
    });
  }

  function runSearch() {
    const query = searchInput ? searchInput.value.trim().toLowerCase() : '';
    let matchedCount = 0;

    sections.forEach((item) => {
      const matched = !query || item.section.textContent.toLowerCase().includes(query);
      item.section.classList.toggle('search-hidden', Boolean(query) && !matched);
      item.section.classList.toggle('search-hit', Boolean(query) && matched);

      if (query && matched) {
        matchedCount += 1;
        setCollapsed(item.section, false);
      }
    });

    tocLinks.forEach((link) => {
      const id = decodeURIComponent(link.getAttribute('href').slice(1));
      const section = sectionMap.get(id);
      const visible = section ? !section.classList.contains('search-hidden') : true;
      link.style.display = visible ? '' : 'none';
    });

    if (resultMeta) {
      if (!query) {
        resultMeta.textContent = '검색 대기 중';
      } else if (matchedCount === 0) {
        resultMeta.textContent = '일치 섹션 없음';
      } else {
        resultMeta.textContent = `${matchedCount}개 섹션 일치`;
      }
    }

    syncTocActive();
  }

  function bindTocBehavior() {
    window.addEventListener('scroll', syncTocActive, { passive: true });
    window.addEventListener('hashchange', syncTocActive);
    syncTocActive();
  }

  function syncTocActive() {
    const visibleSections = sections.filter((item) => !item.section.classList.contains('search-hidden'));
    if (!visibleSections.length) return;

    let currentId = visibleSections[0].id;
    const threshold = 150;

    visibleSections.forEach((item) => {
      const top = item.section.getBoundingClientRect().top;
      if (top <= threshold) currentId = item.id;
    });

    sections.forEach((item) => {
      item.link.classList.toggle(
        'active',
        item.id === currentId && !item.section.classList.contains('search-hidden')
      );
    });
  }

  function bindBackToTop() {
    if (!backToTopBtn) return;

    const toggleBtn = () => {
      backToTopBtn.classList.toggle('visible', window.scrollY > 300);
    };

    window.addEventListener('scroll', toggleBtn, { passive: true });
    toggleBtn();

    backToTopBtn.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  function setCollapsed(section, collapsed) {
    section.classList.toggle('is-collapsed', collapsed);
    const toggleBtn = section.querySelector('.doc-section-actions button[data-action="toggle"]');
    if (!toggleBtn) return;
    toggleBtn.textContent = collapsed ? '[펼치기]' : '[접기]';
    toggleBtn.setAttribute('aria-expanded', String(!collapsed));
  }

  async function copyText(text) {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (_) {
      // fallback below
    }

    try {
      const area = document.createElement('textarea');
      area.value = text;
      document.body.appendChild(area);
      area.select();
      const copied = document.execCommand('copy');
      area.remove();
      return copied;
    } catch (_) {
      return false;
    }
  }
})();
