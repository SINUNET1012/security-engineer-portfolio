(() => {
  const panels = Array.from(document.querySelectorAll(".content .panel"));
  if (!panels.length) return;

  const tocLinks = Array.from(document.querySelectorAll(".toc a[href^='#']"));
  const backToTopBtn = document.getElementById("back-to-top-btn");
  const expandAllBtn = document.getElementById("asset-expand-all-btn");
  const collapseAllBtn = document.getElementById("asset-collapse-all-btn");
  const focusSearchBtn = document.getElementById("asset-focus-search-btn");
  const fileSearchInput = document.getElementById("search-input");

  const panelMap = new Map(panels.map((panel) => [panel.id, panel]));

  attachSectionActions();
  bindControls();
  bindTocBehavior();
  bindBackToTop();

  function attachSectionActions() {
    panels.forEach((panel) => {
      const heading = panel.querySelector(":scope > h2");
      if (!heading) return;

      const actions = document.createElement("span");
      actions.className = "section-actions";

      const toggleBtn = document.createElement("button");
      toggleBtn.type = "button";
      toggleBtn.className = "section-toggle-btn";
      toggleBtn.textContent = "[접기]";
      toggleBtn.setAttribute("aria-expanded", "true");

      const linkBtn = document.createElement("button");
      linkBtn.type = "button";
      linkBtn.className = "section-link-btn";
      linkBtn.textContent = "[링크]";
      linkBtn.title = "문단 링크 복사";

      actions.append(toggleBtn, linkBtn);
      heading.append(actions);

      const body = document.createElement("div");
      body.className = "panel-body";
      while (heading.nextSibling) {
        body.appendChild(heading.nextSibling);
      }
      panel.appendChild(body);

      toggleBtn.addEventListener("click", () => {
        setCollapsed(panel, !panel.classList.contains("is-collapsed"));
      });

      linkBtn.addEventListener("click", async () => {
        const url = new URL(`#${panel.id}`, window.location.href).href;
        const copied = await copyText(url);
        const prev = linkBtn.textContent;
        linkBtn.textContent = copied ? "[복사됨]" : "[실패]";
        window.setTimeout(() => {
          linkBtn.textContent = prev;
        }, 850);
      });
    });
  }

  function bindControls() {
    expandAllBtn?.addEventListener("click", () => {
      panels.forEach((panel) => setCollapsed(panel, false));
    });

    collapseAllBtn?.addEventListener("click", () => {
      panels.forEach((panel) => setCollapsed(panel, true));
    });

    focusSearchBtn?.addEventListener("click", () => {
      if (fileSearchInput) {
        fileSearchInput.focus();
        fileSearchInput.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    });

    window.addEventListener("keydown", (event) => {
      const target = event.target;
      const isTypingElement =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        (target instanceof HTMLElement && target.isContentEditable);

      if (event.key === "/" && !isTypingElement) {
        if (fileSearchInput) {
          event.preventDefault();
          fileSearchInput.focus();
        }
      }
    });
  }

  function bindTocBehavior() {
    const syncActive = () => {
      const visiblePanels = panels.filter((panel) => !panel.classList.contains("search-hidden"));
      if (!visiblePanels.length) return;

      let currentId = visiblePanels[0].id;
      const threshold = 160;

      visiblePanels.forEach((panel) => {
        const top = panel.getBoundingClientRect().top;
        if (top <= threshold) currentId = panel.id;
      });

      tocLinks.forEach((link) => {
        const id = decodeURIComponent(link.getAttribute("href").slice(1));
        const panel = panelMap.get(id);
        const visible = panel ? !panel.classList.contains("search-hidden") : true;
        link.style.display = visible ? "" : "none";
        link.classList.toggle("active", id === currentId && visible);
      });
    };

    window.addEventListener("scroll", syncActive, { passive: true });
    window.addEventListener("hashchange", syncActive);
    syncActive();
  }

  function bindBackToTop() {
    if (!backToTopBtn) return;
    const toggleBtn = () => {
      backToTopBtn.classList.toggle("visible", window.scrollY > 320);
    };
    window.addEventListener("scroll", toggleBtn, { passive: true });
    toggleBtn();

    backToTopBtn.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  function setCollapsed(panel, collapsed) {
    panel.classList.toggle("is-collapsed", collapsed);
    const btn = panel.querySelector(".section-toggle-btn");
    if (!btn) return;
    btn.textContent = collapsed ? "[펼치기]" : "[접기]";
    btn.setAttribute("aria-expanded", String(!collapsed));
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
      const area = document.createElement("textarea");
      area.value = text;
      document.body.appendChild(area);
      area.select();
      const copied = document.execCommand("copy");
      area.remove();
      return copied;
    } catch (err) {
      return false;
    }
  }
})();
