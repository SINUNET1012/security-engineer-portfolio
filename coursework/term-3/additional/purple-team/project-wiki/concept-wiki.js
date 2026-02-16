(() => {
  const panels = Array.from(document.querySelectorAll('.content .panel'));
  if (!panels.length) return;

  const labels = {
    fold: '[\uC811\uAE30]',
    open: '[\uD3BC\uCE58\uAE30]',
    link: '[\uB9C1\uD06C]',
    copied: '[\uBCF5\uC0AC\uB428]',
    copyFail: '[\uC2E4\uD328]',
    tocFold: '\uBAA9\uCC28 \uC811\uAE30',
    tocOpen: '\uBAA9\uCC28 \uD3BC\uCE58\uAE30',
    idle: '\uAC80\uC0C9 \uB300\uAE30 \uC911',
    noMatch: '\uC77C\uCE58 \uC139\uC158 \uC5C6\uC74C',
    matches: '\uAC1C \uC139\uC158 \uC77C\uCE58'
  };

  const searchInput = document.getElementById('wiki-search-input');
  const clearSearchBtn = document.getElementById('clear-search-btn');
  const resultText = document.getElementById('search-result-text');
  const expandAllBtn = document.getElementById('expand-all-btn');
  const collapseAllBtn = document.getElementById('collapse-all-btn');
  const toc = document.querySelector('.toc');
  const tocCollapseBtn = document.getElementById('toc-collapse-btn');
  const tocLinks = Array.from(document.querySelectorAll('.toc a[href^="#"]'));
  const backToTopBtn = document.getElementById('back-to-top-btn');
  const toolTabs = Array.from(document.querySelectorAll('.tool-tabs .tab'));

  const panelMap = new Map(panels.map((panel) => [panel.id, panel]));

  attachSectionActions();
  bindControls();
  bindSearch();
  bindTocBehavior();
  bindBackToTop();
  bindTabs();
  syncTocActive();

  function attachSectionActions() {
    panels.forEach((panel) => {
      const heading = panel.querySelector(':scope > h2');
      if (!heading) return;

      const rawTitleNode = heading.childNodes[0];
      const titleText =
        rawTitleNode && rawTitleNode.textContent
          ? rawTitleNode.textContent.trim()
          : heading.textContent.trim();

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
      linkBtn.title = '\uBB38\uB2E8 \uB9C1\uD06C \uBCF5\uC0AC';
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
        tocCollapseBtn.textContent = toc?.classList.contains('toc-collapsed')
          ? labels.tocOpen
          : labels.tocFold;
      }
    });
  }

  function bindSearch() {
    if (!searchInput) return;

    const runSearch = () => {
      const query = searchInput.value.trim().toLowerCase();
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

    searchInput.addEventListener('input', runSearch);

    clearSearchBtn?.addEventListener('click', () => {
      searchInput.value = '';
      runSearch();
      searchInput.focus();
    });

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

  function bindTocBehavior() {
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
          searchInput?.focus();
        }
      });
    });
  }

  function syncTocActive() {
    const visiblePanels = panels.filter((panel) => !panel.classList.contains('search-hidden'));
    if (!visiblePanels.length) return;

    let currentId = visiblePanels[0].id;
    const threshold = 160;

    visiblePanels.forEach((panel) => {
      const top = panel.getBoundingClientRect().top;
      if (top <= threshold) {
        currentId = panel.id;
      }
    });

    tocLinks.forEach((link) => {
      const targetId = decodeURIComponent(link.getAttribute('href').slice(1));
      link.classList.toggle('active', targetId === currentId);
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
    } catch (err) {
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
    } catch (err) {
      return false;
    }
  }
})();
