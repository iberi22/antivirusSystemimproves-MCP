(function(){
  // --- Global loader helpers (anime.js required) ---
  let __loaderAnim = null;
  let __loaderHidden = false;
  function startLoader() {
    try {
      const overlay = document.getElementById('owLoader');
      if (!overlay) return;
      // Respect reduced motion
      const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (reduce) {
        overlay.classList.remove('hidden');
        return;
      }
      if (typeof window.anime !== 'function') return;
      overlay.classList.remove('hidden');
      __loaderAnim = window.anime({
        targets: '.ow-loader-dot',
        scale: [{ value: 1.15 }, { value: 0.7 }],
        opacity: [{ value: 1 }, { value: 0.5 }],
        easing: 'easeInOutSine',
        direction: 'alternate',
        duration: 700,
        delay: window.anime.stagger(120, { from: 'center' }),
        loop: true,
      });
    } catch {}
  }
  function hideLoader() {
    try {
      if (__loaderHidden) return;
      const overlay = document.getElementById('owLoader');
      if (!overlay) return;
      __loaderHidden = true;
      if (__loaderAnim && typeof __loaderAnim.pause === 'function') {
        try { __loaderAnim.pause(); } catch {}
      }
      if (typeof window.anime === 'function') {
        window.anime({
          targets: '#owLoader',
          opacity: [1, 0],
          duration: 350,
          easing: 'easeOutQuad',
          complete: () => { overlay.classList.add('hidden'); }
        });
      } else {
        overlay.classList.add('hidden');
      }
    } catch {}
  }

  // Early bind to first-data event to avoid race conditions with app.js
  try {
    window.addEventListener('ow:core:update', () => hideLoader(), { once: true });
    if (window.__owCoreFirstDataReceived) {
      // Data already arrived before this script bound the listener
      hideLoader();
    }
  } catch {}
  async function injectHeader() {
    const mount = document.getElementById('owHeader');
    if (!mount) return null;
    try {
      const r = await fetch('/static/header.html', { cache: 'no-store' });
      const html = await r.text();
      mount.innerHTML = html;
      // Activar tab
      const path = location.pathname || '/';
      const isGB = path.startsWith('/gamebooster');
      const tabs = mount.querySelectorAll('#owTabs a');
      tabs.forEach(a => {
        const isActive = (a.dataset.tab === (isGB ? 'gamebooster' : 'dashboard'));
        a.classList.toggle('bg-blue-600', isActive);
        a.classList.toggle('text-white', isActive);
        a.classList.toggle('bg-gray-200', !isActive);
        a.classList.toggle('dark:bg-gray-700', !isActive);
        a.classList.toggle('text-gray-800', !isActive);
        a.classList.toggle('dark:text-gray-100', !isActive);
      });
      return mount;
    } catch {}
    return null;
  }

  function updateHeaderFromCore(core){
    try {
      const cpu = ((core?.cpu_percent) ?? 0).toFixed(1);
      const ram = ((core?.memory?.percent) ?? 0).toFixed(1);
      let diskPct = null;
      if (Array.isArray(core?.disks)) {
        const disks = core.disks;
        diskPct = disks.find(d => (d.mountpoint||'').toLowerCase().startsWith('c:'))?.percent;
        if (diskPct == null && disks.length) diskPct = Math.max(...disks.map(d => d.percent||0));
      }
      const disk = ((diskPct ?? 0)).toFixed(1);
      const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
      set('hdrCpu', cpu);
      set('hdrRam', ram);
      set('hdrDisk', disk);
    } catch {}
  }

  let __hdrInfoTimer = null;
  async function pollInfoHdr() {
    try {
      const res = await fetch('/api/info?sections=core,diagnostics,sensors', { cache: 'no-store' });
      if (!res.ok) throw new Error('bad status');
      const data = await res.json();
      const core = data?.sections?.core || null;
      const s = data?.sections?.diagnostics || {};
      const sensors = data?.sections?.sensors || null;
      // Actualizar chips de header
      updateHeaderFromCore(core);
      // Actualizar badge de estado
      const badge = document.getElementById('diagStatusBadgeHdr');
      const base = 'inline-flex items-center gap-1 text-xs px-2 py-1 rounded ';
      const st = (s.status || 'idle').toLowerCase();
      const map = {
        idle: 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200',
        running: 'bg-blue-100 dark:bg-blue-900/40 text-blue-800 dark:text-blue-200',
        done: 'bg-green-100 dark:bg-green-900/40 text-green-800 dark:text-green-200',
        completed: 'bg-green-100 dark:bg-green-900/40 text-green-800 dark:text-green-200',
        error: 'bg-red-100 dark:bg-red-900/40 text-red-800 dark:text-red-200',
        failed: 'bg-red-100 dark:bg-red-900/40 text-red-800 dark:text-red-200'
      };
      if (badge) {
        badge.className = base + (map[st] || map.idle);
        badge.textContent = st.charAt(0).toUpperCase() + st.slice(1);
      }
      // Emitir eventos unificados
      window.dispatchEvent(new CustomEvent('ow:core:update', { detail: core }));
      window.dispatchEvent(new CustomEvent('ow:diagnostics:status', { detail: s }));
      if (sensors) window.dispatchEvent(new CustomEvent('ow:sensors:update', { detail: sensors }));
      // Cadencia dinámica
      const delay = (st === 'running') ? 2000 : 4500;
      __hdrInfoTimer = setTimeout(pollInfoHdr, delay);
    } catch {
      // Fallback: reintentar más lento para evitar thundering herd
      __hdrInfoTimer = setTimeout(pollInfoHdr, 5000);
    }
  }

  function hookHeaderActions() {
    const statusEl = document.getElementById('status');
    const showStatus = (msg, type='info') => {
      if (!statusEl) return;
      statusEl.classList.remove('hidden');
      statusEl.textContent = msg;
      const base = 'px-4 py-2 rounded border text-sm';
      const map = {
        info: 'bg-blue-50 border-blue-200 text-blue-800 dark:bg-blue-900/30 dark:border-blue-800 dark:text-blue-200',
        ok: 'bg-green-50 border-green-200 text-green-800 dark:bg-green-900/30 dark:border-green-800 dark:text-green-200',
        err: 'bg-red-50 border-red-200 text-red-800 dark:bg-red-900/30 dark:border-red-800 dark:text-red-200'
      };
      statusEl.className = `${base} ${map[type] || map.info}`;
    };

    const btnDiag = document.getElementById('btnDiag');
    const btnPrepare = document.getElementById('btnPrepare');
    btnDiag?.addEventListener('click', async () => {
      const icon = btnDiag.querySelector('.material-symbols-outlined');
      // Busy UI
      btnDiag.disabled = true;
      btnDiag.classList.add('opacity-60','cursor-not-allowed');
      if (icon) icon.textContent = 'progress_activity';
      try {
        const r = await fetch('/api/action/diagnostics', { method: 'POST' });
        await r.json().catch(() => ({}));
        showStatus('Diagnóstico aceptado (asíncrono).', r.ok ? 'ok' : 'err');
        // Avisar a otras vistas/paneles
        window.dispatchEvent(new CustomEvent('ow:diagnostics:started', { detail: { ok: !!r.ok } }));
      } catch (e) {
        showStatus('Error al lanzar diagnóstico.', 'err');
        window.dispatchEvent(new CustomEvent('ow:diagnostics:started', { detail: { ok: false, error: true } }));
      } finally {
        // Restore UI
        btnDiag.disabled = false;
        btnDiag.classList.remove('opacity-60','cursor-not-allowed');
        if (icon) icon.textContent = 'play_arrow';
      }
    });
    btnPrepare?.addEventListener('click', async () => {
      const defaultText = btnPrepare.textContent;
      btnPrepare.disabled = true;
      btnPrepare.classList.add('opacity-60','cursor-not-allowed');
      btnPrepare.textContent = 'Copiando...';
      try {
        const r = await fetch('/api/action/report/prepare', { method: 'POST' });
        const j = await r.json().catch(() => ({}));
        const ok = (j && j.status === 'ok');
        showStatus(ok ? 'Reporte preparado.' : 'Error preparando reporte.', ok ? 'ok' : 'err');
        window.dispatchEvent(new CustomEvent('ow:report:prepare:done', { detail: { ok } }));
      } catch (e) {
        showStatus('Error al preparar reporte.', 'err');
        window.dispatchEvent(new CustomEvent('ow:report:prepare:done', { detail: { ok: false, error: true } }));
      } finally {
        btnPrepare.disabled = false;
        btnPrepare.classList.remove('opacity-60','cursor-not-allowed');
        btnPrepare.textContent = defaultText || 'Reporte';
      }
    });
  }

  document.addEventListener('DOMContentLoaded', async () => {
    // Start loader animation early
    startLoader();
    const el = await injectHeader();
    if (el) {
      hookHeaderActions();
      // Única fuente de estado para header y dashboard (eventos)
      if (__hdrInfoTimer) { clearTimeout(__hdrInfoTimer); __hdrInfoTimer = null; }
      pollInfoHdr();
    }
  });
})();
