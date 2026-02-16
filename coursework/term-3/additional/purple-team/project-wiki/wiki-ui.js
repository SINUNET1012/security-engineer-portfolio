(() => {
  const labels = {
    fold: '[접기]',
    open: '[펼치기]',
    link: '[링크]',
    copied: '[복사됨]',
    copyFail: '[실패]',
    tocFold: '목차 접기',
    tocOpen: '목차 펼치기',
    idle: '검색 대기 중',
    noMatch: '일치 섹션 없음',
    matches: '개 섹션 일치',
  };

  const panels = Array.from(document.querySelectorAll('.content .panel'));
  const toc = document.querySelector('.toc');
  const tocLinks = Array.from(document.querySelectorAll('.toc a[href^="#"]'));
  const backToTopBtn = document.getElementById('back-to-top-btn');
  const toolTabs = Array.from(document.querySelectorAll('.tool-tabs .tab'));

  const pageSearchInput = document.getElementById('page-search-input');
  const clearSearchBtn = document.getElementById('clear-search-btn');
  const resultText = document.getElementById('search-result-text');
  const expandAllBtn = document.getElementById('expand-all-btn');
  const collapseAllBtn = document.getElementById('collapse-all-btn');
  const tocCollapseBtn = document.getElementById('toc-collapse-btn');
  const focusFileSearchBtn = document.getElementById('focus-file-search-btn');
  const fileSearchInput = document.getElementById('search-input');

  const globalSearchInput = document.getElementById('global-search-input');
  const randomPageLink = document.getElementById('random-page-link');
  const pages = Array.isArray(window.WIKI_PAGES) ? window.WIKI_PAGES : null;
  const wikiBaseUrl = getWikiBaseUrl();

  const panelMap = new Map(panels.map((panel) => [panel.id, panel]));

  attachSectionActions();
  bindControls();
  bindPageSearch();
  bindGlobalSearch();
  bindTocBehavior();
  bindBackToTop();
  bindTabs();
  syncTocActive();

  function attachSectionActions() {
    if (!panels.length) return;

    panels.forEach((panel) => {
      const heading = panel.querySelector(':scope > h2');
      if (!heading) return;

      const rawTitleNode = heading.childNodes[0];
      const titleText =
        rawTitleNode && rawTitleNode.textContent ? rawTitleNode.textContent.trim() : heading.textContent.trim();

      const actions = document.createElement('span');
      actions.className = 'section-actions';

      const toggleBtn = document.createElement('button');
      toggleBtn.type = 'button';
      toggleBtn.className = 'section-toggle-btn';
      toggleBtn.textContent = labels.fold;
      toggleBtn.setAttribute('aria-expanded', 'true');
      toggleBtn.setAttribute('aria-label', `${titleText} ${labels.fold}`);

      const linkBtn = document.createElement('button');
      linkBtn.type = 'button';
      linkBtn.className = 'section-link-btn';
      linkBtn.textContent = labels.link;
      linkBtn.title = '문단 링크 복사';
      linkBtn.setAttribute('aria-label', `${titleText} ${labels.link}`);

      actions.append(toggleBtn, linkBtn);
      heading.append(actions);

      const body = document.createElement('div');
      body.className = 'panel-body';
      while (heading.nextSibling) {
        body.appendChild(heading.nextSibling);
      }
      panel.appendChild(body);

      toggleBtn.addEventListener('click', () => {
        setCollapsed(panel, !panel.classList.contains('is-collapsed'));
      });

      linkBtn.addEventListener('click', async () => {
        const url = new URL(`#${panel.id}`, window.location.href).href;
        const copied = await copyText(url);
        const prev = linkBtn.textContent;
        linkBtn.textContent = copied ? labels.copied : labels.copyFail;
        window.setTimeout(() => {
          linkBtn.textContent = prev;
        }, 850);
      });
    });
  }

  function bindControls() {
    expandAllBtn?.addEventListener('click', () => {
      panels.forEach((panel) => setCollapsed(panel, false));
    });

    collapseAllBtn?.addEventListener('click', () => {
      panels.forEach((panel) => setCollapsed(panel, true));
    });

    tocCollapseBtn?.addEventListener('click', () => {
      toc?.classList.toggle('toc-collapsed');
      if (tocCollapseBtn) {
        tocCollapseBtn.textContent = toc?.classList.contains('toc-collapsed') ? labels.tocOpen : labels.tocFold;
      }
    });

    focusFileSearchBtn?.addEventListener('click', () => {
      if (!fileSearchInput) return;
      fileSearchInput.focus();
      fileSearchInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });

    randomPageLink?.addEventListener('click', (event) => {
      if (!pages || !pages.length) return;
      event.preventDefault();
      const pick = pages[Math.floor(Math.random() * pages.length)];
      if (pick && pick.href) window.location.href = resolveWikiHref(pick.href);
    });

    window.addEventListener('keydown', (event) => {
      const target = event.target;
      const isTypingElement =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        (target instanceof HTMLElement && target.isContentEditable);

      if (event.key === '/' && !isTypingElement) {
        const input = globalSearchInput || pageSearchInput || fileSearchInput;
        if (!input) return;
        event.preventDefault();
        input.focus();
      }
    });
  }

  function bindPageSearch() {
    if (!pageSearchInput || !panels.length) return;

    const runSearch = () => {
      const query = pageSearchInput.value.trim().toLowerCase();
      let matchedCount = 0;

      panels.forEach((panel) => {
        const matched = !query || panel.textContent.toLowerCase().includes(query);
        panel.classList.toggle('search-hidden', Boolean(query) && !matched);
        panel.classList.toggle('search-hit', Boolean(query) && matched);

        if (query && matched) {
          matchedCount += 1;
          setCollapsed(panel, false);
        }
      });

      tocLinks.forEach((link) => {
        const id = decodeURIComponent(link.getAttribute('href').slice(1));
        const panel = panelMap.get(id);
        const visible = panel ? !panel.classList.contains('search-hidden') : true;
        link.style.display = query && !visible ? 'none' : '';
      });

      if (resultText) {
        if (!query) {
          resultText.textContent = labels.idle;
        } else if (matchedCount === 0) {
          resultText.textContent = labels.noMatch;
        } else {
          resultText.textContent = `${matchedCount}${labels.matches}`;
        }
      }

      syncTocActive();
    };

    pageSearchInput.addEventListener('input', runSearch);

    clearSearchBtn?.addEventListener('click', () => {
      pageSearchInput.value = '';
      runSearch();
      pageSearchInput.focus();
    });
  }

  function bindGlobalSearch() {
    if (!globalSearchInput) return;
    if (!pages || !pages.length) return;

    const suggestBox = ensureSuggestBox();
    let activeIndex = -1;
    let lastMatches = [];
    let blurTimer = null;

    globalSearchInput.setAttribute('autocomplete', 'off');
    globalSearchInput.setAttribute('spellcheck', 'false');

    globalSearchInput.addEventListener('input', () => {
      const query = globalSearchInput.value.trim().toLowerCase();
      if (!query) {
        hideSuggest();
        return;
      }

      lastMatches = getMatches(query);
      activeIndex = -1;
      renderSuggest(query, lastMatches);
    });

    globalSearchInput.addEventListener('keydown', (event) => {
      if (suggestBox.hidden) return;

      if (event.key === 'Escape') {
        event.preventDefault();
        hideSuggest();
        return;
      }

      if (event.key === 'ArrowDown') {
        event.preventDefault();
        setActiveIndex(Math.min(activeIndex + 1, lastMatches.length - 1));
        return;
      }

      if (event.key === 'ArrowUp') {
        event.preventDefault();
        setActiveIndex(Math.max(activeIndex - 1, 0));
        return;
      }

      if (event.key === 'Enter') {
        const pick = lastMatches[activeIndex] || lastMatches[0];
        if (!pick) return;
        event.preventDefault();
        window.location.href = resolveWikiHref(pick.href);
      }
    });

    globalSearchInput.addEventListener('blur', () => {
      blurTimer = window.setTimeout(() => {
        hideSuggest();
      }, 120);
    });

    globalSearchInput.addEventListener('focus', () => {
      if (blurTimer) window.clearTimeout(blurTimer);
      const query = globalSearchInput.value.trim().toLowerCase();
      if (!query) return;
      lastMatches = getMatches(query);
      renderSuggest(query, lastMatches);
    });

    document.addEventListener('click', (event) => {
      if (!(event.target instanceof Node)) return;
      const inside = suggestBox.contains(event.target) || globalSearchInput.contains(event.target);
      if (!inside) hideSuggest();
    });

    function ensureSuggestBox() {
      const existing = document.getElementById('global-search-suggest');
      if (existing) return existing;

      const box = document.createElement('div');
      box.id = 'global-search-suggest';
      box.className = 'search-suggest';
      box.hidden = true;
      globalSearchInput.parentElement?.appendChild(box);
      return box;
    }

    function getMatches(query) {
      const candidates = [];

      pages.forEach((page) => {
        if (!page || !page.title || !page.href) return;
        const title = String(page.title);
        const summary = page.summary ? String(page.summary) : '';
        const hay = `${title} ${summary}`.toLowerCase();
        const idx = hay.indexOf(query);
        if (idx === -1) return;

        const titleLower = title.toLowerCase();
        const score =
          titleLower.startsWith(query) ? 0 : titleLower.includes(query) ? 50 + titleLower.indexOf(query) : 100 + idx;

        candidates.push({ ...page, _score: score });
      });

      candidates.sort((a, b) => a._score - b._score || String(a.title).localeCompare(String(b.title), 'ko-KR'));
      return candidates.slice(0, 10);
    }

    function renderSuggest(query, matches) {
      suggestBox.innerHTML = '';

      const head = document.createElement('div');
      head.className = 'suggest-head';
      head.textContent = matches.length ? `검색 결과: ${matches.length}건` : '검색 결과 없음';
      suggestBox.appendChild(head);

      if (!matches.length) {
        const empty = document.createElement('a');
        empty.href = '#';
        empty.addEventListener('click', (e) => e.preventDefault());
        empty.textContent = `"${query}"에 해당하는 문서가 없습니다.`;
        suggestBox.appendChild(empty);
        suggestBox.hidden = false;
        return;
      }

      matches.forEach((page, idx) => {
        const a = document.createElement('a');
        a.href = resolveWikiHref(page.href);
        a.dataset.idx = String(idx);

        const title = document.createElement('div');
        title.textContent = page.title;
        a.appendChild(title);

        if (page.summary) {
          const hint = document.createElement('span');
          hint.className = 'hint';
          hint.textContent = page.summary;
          a.appendChild(hint);
        }

        a.addEventListener('mouseenter', () => setActiveIndex(idx));
        a.addEventListener('mousedown', () => {
          // Prevent input blur before navigation.
          if (blurTimer) window.clearTimeout(blurTimer);
        });

        suggestBox.appendChild(a);
      });

      suggestBox.hidden = false;
    }

    function setActiveIndex(next) {
      activeIndex = next;
      const links = Array.from(suggestBox.querySelectorAll('a[data-idx]'));
      links.forEach((el) => {
        const idx = Number(el.dataset.idx);
        el.classList.toggle('active', idx === activeIndex);
      });
    }

    function hideSuggest() {
      suggestBox.hidden = true;
      suggestBox.innerHTML = '';
      activeIndex = -1;
    }
  }

  function bindTocBehavior() {
    if (!tocLinks.length || !panels.length) return;

    window.addEventListener('scroll', syncTocActive, { passive: true });
    window.addEventListener('hashchange', syncTocActive);

    tocLinks.forEach((link) => {
      link.addEventListener('click', () => {
        window.setTimeout(syncTocActive, 20);
      });
    });
  }

  function bindBackToTop() {
    if (!backToTopBtn) return;

    const toggleBtn = () => {
      backToTopBtn.classList.toggle('visible', window.scrollY > 360);
    };

    window.addEventListener('scroll', toggleBtn, { passive: true });
    toggleBtn();

    backToTopBtn.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  function bindTabs() {
    if (!toolTabs.length) return;

    toolTabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        toolTabs.forEach((btn) => btn.classList.remove('active'));
        tab.classList.add('active');

        const mode = tab.dataset.mode;
        if (mode === 'fold') {
          collapseAllBtn?.focus();
        } else if (mode === 'nav') {
          tocLinks[0]?.focus();
        } else {
          (pageSearchInput || globalSearchInput)?.focus();
        }
      });
    });
  }

  function syncTocActive() {
    if (!tocLinks.length || !panels.length) return;

    const visiblePanels = panels.filter((panel) => !panel.classList.contains('search-hidden'));
    if (!visiblePanels.length) return;

    let currentId = visiblePanels[0].id;
    const threshold = 160;

    visiblePanels.forEach((panel) => {
      const top = panel.getBoundingClientRect().top;
      if (top <= threshold) currentId = panel.id;
    });

    tocLinks.forEach((link) => {
      const targetId = decodeURIComponent(link.getAttribute('href').slice(1));
      const panel = panelMap.get(targetId);
      const visible = panel ? !panel.classList.contains('search-hidden') : true;
      link.style.display = visible ? '' : 'none';
      link.classList.toggle('active', targetId === currentId && visible);
    });
  }

  function setCollapsed(panel, collapsed) {
    panel.classList.toggle('is-collapsed', collapsed);
    const btn = panel.querySelector('.section-toggle-btn');
    if (!btn) return;
    btn.textContent = collapsed ? labels.open : labels.fold;
    btn.setAttribute('aria-expanded', String(!collapsed));
  }

  async function copyText(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
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

  function getWikiBaseUrl() {
    if (typeof window.WIKI_BASE_URL === 'string' && window.WIKI_BASE_URL) {
      return window.WIKI_BASE_URL;
    }

    const script = document.querySelector('script[src$="wiki-pages.js"]');
    if (script && script.src) {
      try {
        return new URL('.', script.src).href;
      } catch (_) {
        // fall through
      }
    }

    return new URL('.', window.location.href).href;
  }

  function resolveWikiHref(href) {
    try {
      return new URL(href, wikiBaseUrl).href;
    } catch (_) {
      return href;
    }
  }
})();
