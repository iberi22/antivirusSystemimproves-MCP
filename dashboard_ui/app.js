(() => {
  const cpuCtx = document.getElementById('cpuChart').getContext('2d');
  const cpuCountEl = document.getElementById('cpuCount');
  const memBar = document.getElementById('memBar');
  const memPercentEl = document.getElementById('memPercent');
  const diskList = document.getElementById('diskList');
  const statusEl = document.getElementById('status');
  const diagBar = document.getElementById('diagBar');
  const diagText = document.getElementById('diagText');

  const tblProcMem = document.getElementById('tblProcMem');
  const tblProcCpu = document.getElementById('tblProcCpu');
  const tblConns = document.getElementById('tblConns');

  const refreshProcMem = document.getElementById('refreshProcMem');
  const refreshProcCpu = document.getElementById('refreshProcCpu');
  const refreshConns = document.getElementById('refreshConns');
  const refreshFsHeavy = document.getElementById('refreshFsHeavy');
  const refreshHosts = document.getElementById('refreshHosts');

  const fsHeavy = document.getElementById('fsHeavy');
  const tblHosts = document.getElementById('tblHosts');
  const tblNetProcs = document.getElementById('tblNetProcs');

  // Sensors placeholders
  const sensorsCpuTemp = document.getElementById('sensorsCpuTemp');
  const sensorsGpuTemp = document.getElementById('sensorsGpuTemp');
  const sensorsRamTemp = document.getElementById('sensorsRamTemp');
  const sensorsDiskTemp = document.getElementById('sensorsDiskTemp');
  const sensorsNetName = document.getElementById('sensorsNetName');
  const sensorsNetMbps = document.getElementById('sensorsNetMbps');
  const btnDiagDetail = document.getElementById('btnDiagDetail');
  const diagDetailBox = document.getElementById('diagDetailBox');
  const diagDetail = document.getElementById('diagDetail');
  const diagStatusBadge = document.getElementById('diagStatusBadge');
  const btnDiagCopy = document.getElementById('btnDiagCopy');
  const diagError = document.getElementById('diagError');
  const diagErrorMsg = document.getElementById('diagErrorMsg');
  const usageCpu = document.getElementById('sensorsUsageCpu');
  const usageGpu = document.getElementById('sensorsUsageGpu');
  const usageRam = document.getElementById('sensorsUsageRam');
  const usageDisk = document.getElementById('sensorsUsageDisk');
  let lastDiagDetailText = '';

  // GameBooster elements
  const gbProfile = document.getElementById('gbProfile');
  const gbPreviewBtn = document.getElementById('gbPreview');
  const gbLoadBtn = document.getElementById('gbLoad');
  const gbTable = document.getElementById('tblGB');
  const gbPreviewBox = document.getElementById('gbPreviewBox');

  const cpuData = { labels: [], datasets: [{ label: 'CPU %', data: [], borderColor: '#2563eb', backgroundColor: 'rgba(37,99,235,0.15)', fill: true, pointRadius: 0, tension: 0.3 }] };
  const cpuChart = new Chart(cpuCtx, {
    type: 'line',
    data: cpuData,
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      scales: { y: { min: 0, max: 100, ticks: { stepSize: 25 } }, x: { display: false } },
      plugins: { legend: { display: false } }
    }
  });

  // ---------------------- GameBooster logic ----------------------
  async function loadGBProfiles() {
    if (!gbProfile) return;
    try {
      const r = await fetch('/api/profiles');
      if (!r.ok) return;
      const j = await r.json();
      const arr = Array.isArray(j.profiles) ? j.profiles : [];
      gbProfile.innerHTML = arr.map(p => `<option value="${p.name}">${p.name} (${p.actions_count||0})</option>`).join('');
    } catch {}
  }

  async function previewGBProfile() {
    if (!gbProfile || !gbPreviewBox) return;
    const name = gbProfile.value;
    if (!name) return;
    try {
      const r = await fetch(`/api/profiles/preview?name=${encodeURIComponent(name)}`);
      if (!r.ok) return;
      const j = await r.json();
      const acts = (j.actions||[]).map(a => `• ${a.key}: ${a.description}${a.requires_elevation? ' (elevación)': ''}`).join('\n');
      gbPreviewBox.textContent = `Perfil: ${j.name}\n${j.summary||''}\n\nAcciones:\n${acts}`.trim();
      gbPreviewBox.classList.remove('hidden');
    } catch {}
  }

  async function loadGBCandidates() {
    if (!gbTable) return;
    try {
      const r = await fetch('/api/gamebooster/candidates?limit=15');
      const j = await r.json();
      const items = Array.isArray(j.candidates) ? j.candidates : [];
      gbTable.innerHTML = items.map(p => `
        <tr class="border-t">
          <td class="px-2 py-1">${p.pid}</td>
          <td class="px-2 py-1">${p.name||''}<div class="text-xs text-gray-500">${p.reason||''}</div></td>
          <td class="px-2 py-1 text-right">${(p.memory_rss||0).toLocaleString()}</td>
          <td class="px-2 py-1 text-right">${(p.cpu_percent??'').toString()}</td>
          <td class="px-2 py-1">
            <div class="flex gap-1">
              <button class="gb-action text-xs text-red-600" data-act="kill" data-pid="${p.pid}">Kill</button>
              <button class="gb-action text-xs text-yellow-600" data-act="isolate" data-pid="${p.pid}">Isolate</button>
              <button class="gb-action text-xs text-gray-700" data-act="unsandbox" data-pid="${p.pid}">Unsandbox</button>
            </div>
          </td>
        </tr>
      `).join('');
    } catch {}
  }

  async function postJSON(url, body) {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body||{}) });
    let j = {};
    try { j = await r.json(); } catch {}
    return { ok: r.ok, data: j };
  }

  gbPreviewBtn?.addEventListener('click', previewGBProfile);
  gbLoadBtn?.addEventListener('click', loadGBCandidates);
  gbTable?.addEventListener('click', async ev => {
    const t = ev.target;
    if (!(t instanceof HTMLElement)) return;
    const btn = t.closest('button.gb-action');
    if (!btn) return;
    const act = btn.getAttribute('data-act');
    const pid = parseInt(btn.getAttribute('data-pid')||'0', 10);
    if (!pid || !act) return;
    try {
      let res;
      if (act === 'kill') {
        res = await postJSON('/api/process/kill', { pid, policy_name: 'Strict', confirm: true });
      } else if (act === 'isolate') {
        res = await postJSON('/api/process/isolate', { pid, policy_name: 'Strict', confirm: true });
      } else if (act === 'unsandbox') {
        res = await postJSON('/api/process/unsandbox', { pid, confirm: true });
      }
      if (res?.data?.ok) {
        showStatus(`Acción ${act} ejecutada sobre PID ${pid}.`, 'ok');
        // refresh lightweight
        loadGBCandidates();
        loadConns();
      } else {
        const err = (res && res.data && (res.data.error || res.data.message)) || 'Fallo en acción';
        showStatus(`Error en ${act}: ${err}`, 'err');
      }
    } catch {
      showStatus(`Error ejecutando ${act}.`, 'err');
    }
  
  });
  

  btnDiagDetail?.addEventListener('click', () => {
    const hidden = diagDetailBox.classList.contains('hidden');
    diagDetailBox.classList.toggle('hidden', !hidden ? true : false);
  });

  btnDiagCopy?.addEventListener('click', async () => {
    try {
      const text = lastDiagDetailText || diagDetail.textContent || '';
      if (!text) return;
      await navigator.clipboard.writeText(text);
      showStatus('Detalle copiado al portapapeles.', 'ok');
    } catch {}
  });

  function pushCpuPoint(val) {
    const now = new Date();
    cpuData.labels.push(now.toLocaleTimeString());
    cpuData.datasets[0].data.push(val);
    if (cpuData.labels.length > 50) {
      cpuData.labels.shift();
      cpuData.datasets[0].data.shift();
    }
    cpuChart.update();
  }

  // Sensors fetch (event-driven with fallback watchdog)
  let lastMetrics = null;
  function applySensors(s) {
    try {
      const set = (el, v, suf='') => { if (el) el.textContent = (v==null? '--' : `${v}${suf}`); };
      set(sensorsCpuTemp, s?.cpu_temp_c);
      set(sensorsGpuTemp, s?.gpu_temp_c);
      set(sensorsRamTemp, s?.ram_temp_c);
      set(sensorsDiskTemp, s?.disk_temp_c);
      if (s?.net) {
        if (s.net.primary && sensorsNetName) sensorsNetName.textContent = s.net.primary;
        const pri = (s.net.interfaces||[]).find(n => n.name === s.net.primary);
        if (pri && pri.speed_mbps != null && sensorsNetMbps) sensorsNetMbps.textContent = pri.speed_mbps;
      }
      // GPU usage unknown -> N/A
      if (usageGpu) usageGpu.textContent = 'N/A';
    } catch {}
  }

  async function loadSensors() {
    try {
      // Prefer MCP sensors if available
      let s = null;
      try {
        const rM = await fetch('/api/mcp/sensors', { cache: 'no-store' });
        if (rM.ok) {
          s = await rM.json();
        }
      } catch {}
      if (!s) {
        const r = await fetch('/api/sensors', { cache: 'no-store' });
        if (!r.ok) return;
        s = await r.json();
      }
      applySensors(s);
    } catch {}
  }

  function setMem(percent) {
    memBar.style.width = `${percent}%`;
    const color = percent > 85 ? 'bg-red-500' : percent > 70 ? 'bg-yellow-500' : 'bg-green-500';
    memBar.className = `h-4 rounded ${color}`;
    memPercentEl.textContent = percent.toFixed(1);
  }

  function diskEmoji(p) {
    const v = Number(p) || 0;
    if (v >= 90) return '🧨';
    if (v >= 75) return '🔥';
    if (v >= 50) return '📀';
    return '🟢';
  }

  function fileEmoji(p) {
    const v = Number(p) || 0;
    if (v >= 60) return '🧨';
    if (v >= 35) return '🔥';
    if (v >= 15) return '📦';
    return '🟢';
  }

  function fileBarColor(p) {
    const v = Number(p) || 0;
    if (v >= 60) return 'bg-red-500';
    if (v >= 35) return 'bg-orange-500';
    if (v >= 15) return 'bg-yellow-500';
    return 'bg-green-500';
  }

  function renderDisks(disks) {
    diskList.innerHTML = '';
    if (!Array.isArray(disks)) return;
    // Order by highest usage first; cap to avoid clutter
    const arr = [...disks].sort((a,b) => (b.percent||0) - (a.percent||0)).slice(0, 8);
    for (const d of arr) {
      const li = document.createElement('li');
      const pct = Math.max(0, Math.min(100, d.percent||0));
      const color = pct > 85 ? 'bg-red-500' : pct > 70 ? 'bg-yellow-500' : 'bg-green-500';
      li.className = 'flex items-center gap-3 p-2 rounded bg-gray-100 dark:bg-gray-700';
      li.innerHTML = `
        <span class="material-symbols-outlined text-gray-700 dark:text-gray-300">hard_drive</span>
        <div class="w-full min-w-0">
          <div class="flex items-center justify-between text-xs font-medium">
            <span class="truncate" title="${d.device} (${d.mountpoint})">${d.device} (${d.mountpoint})</span>
            <span>${pct.toFixed(1)}%</span>
          </div>
          <div class="w-full bg-gray-300 dark:bg-gray-700 rounded h-2 mt-1">
            <div class="h-2 rounded ${color}" style="width:${pct}%"></div>
          </div>
        </div>
      `;
      diskList.appendChild(li);
    }
  }

  function updateMetrics(data) {
    if (!data) return;
    lastMetrics = data;
    if (typeof data.cpu_count === 'number') cpuCountEl.textContent = data.cpu_count;
    if (typeof data.cpu_percent === 'number') pushCpuPoint(data.cpu_percent);
    if (data.memory && typeof data.memory.percent === 'number') setMem(data.memory.percent);
    if (Array.isArray(data.disks)) renderDisks(data.disks);
    // Update usage chips if present
    if (usageCpu) usageCpu.textContent = (data.cpu_percent ?? 0).toFixed(1);
    if (usageRam) usageRam.textContent = (data.memory?.percent ?? 0).toFixed(1);
    if (usageDisk) {
      const disks = data.disks || [];
      let diskPct = disks.find(d => (d.mountpoint||'').toLowerCase().startsWith('c:'))?.percent;
      if (diskPct == null && disks.length) {
        diskPct = Math.max(...disks.map(d => d.percent||0));
      }
      usageDisk.textContent = (diskPct ?? 0).toFixed(1);
    }
  }

  async function fetchMetricsOnce() {
    try {
      // Prefer MCP metrics if available
      let data = null;
      try {
        const rM = await fetch('/api/mcp/metrics', { cache: 'no-store' });
        if (rM.ok) {
          data = await rM.json();
        }
      } catch {}
      if (!data) {
        const res = await fetch('/api/metrics', { cache: 'no-store' });
        if (!res.ok) return;
        data = await res.json();
      }
      updateMetrics(data);
      try { window.__owCoreFirstDataReceived = true; } catch {}
      // Emitir evento para cerrar loader si estamos en fallback HTTP
      try { window.dispatchEvent(new CustomEvent('ow:core:update', { detail: data })); } catch {}
    } catch {}
  }

  async function loadProcMem() {
    // Prefer MCP processes
    let items = null;
    try {
      const rM = await fetch('/api/mcp/processes?by=memory_rss&limit=15', { cache: 'no-store' });
      if (rM.ok) {
        items = await rM.json();
      }
    } catch {}
    if (!items) {
      const res = await fetch('/api/processes/top?by=memory&limit=15', { cache: 'no-store' });
      try { items = await res.json(); } catch { items = []; }
    }
    tblProcMem.innerHTML = items.map(p => `<tr class="border-t"><td class="px-2 py-1">${p.pid}</td><td class="px-2 py-1">${p.name}</td><td class="px-2 py-1 text-right">${(p.memory_rss||0).toLocaleString()}</td></tr>`).join('');
  }

  async function loadProcCpu() {
    // Prefer MCP processes
    let items = null;
    try {
      const rM = await fetch('/api/mcp/processes?by=cpu_percent&limit=15', { cache: 'no-store' });
      if (rM.ok) {
        items = await rM.json();
      }
    } catch {}
    if (!items) {
      const res = await fetch('/api/processes/top?by=cpu&limit=15', { cache: 'no-store' });
      try { items = await res.json(); } catch { items = []; }
    }
    tblProcCpu.innerHTML = items.map(p => `<tr class="border-t"><td class="px-2 py-1">${p.pid}</td><td class="px-2 py-1">${p.name}</td><td class="px-2 py-1 text-right">${(p.cpu_percent||0).toFixed(1)}</td></tr>`).join('');
  }

  async function loadConns() {
    const res = await fetch('/api/connections?limit=50');
    const items = await res.json();
    tblConns.innerHTML = items.map(c => `<tr class="border-t"><td class="px-2 py-1">${c.pid ?? ''}</td><td class="px-2 py-1">${c.process_name ?? ''}</td><td class="px-2 py-1">${c.laddr ?? ''}</td><td class="px-2 py-1">${c.raddr ?? ''}</td><td class="px-2 py-1">${c.status ?? ''}</td></tr>`).join('');
  }

  function mbToGb(mb) { return (mb || 0) / 1024; }
  // helpers definidos arriba (diskEmoji, fileEmoji, fileBarColor)

  async function loadFsHeavy() {
    try {
      const res = await fetch('/api/fs/heavy?limit=5&max_depth=2&min_size_mb=100');
      const data = await res.json();
      fsHeavy.innerHTML = '';
      for (const d of data) {
        const section = document.createElement('div');
        const pct = Math.max(0, Math.min(100, Number(d.percent)||0));
        const emoji = diskEmoji(pct);
        const barColor = pct >= 90 ? 'bg-red-500' : pct >= 75 ? 'bg-orange-500' : pct >= 50 ? 'bg-yellow-500' : 'bg-green-500';
        section.className = 'rounded border p-3 bg-white dark:bg-gray-800 ow-panel';
        section.innerHTML = `
          <div class="flex items-center justify-between mb-2">
            <div class="font-medium"><span class="mr-2">${emoji}</span>${d.device} <span class="text-gray-500">(${d.mountpoint})</span></div>
            <div class="text-sm">${pct.toFixed(1)}%</div>
          </div>
          <div class="w-full bg-gray-300 dark:bg-gray-700 rounded h-2 mb-3">
            <div class="h-2 rounded ${barColor}" style="width:${pct}%"></div>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <div class="font-medium text-sm mb-1">Top carpetas</div>
              <ul class="space-y-2">
                ${(d.dirs||[]).map(x => `
                  <li class="space-y-1">
                    <div class="truncate"><span class="font-mono">${mbToGb(x.size_mb).toFixed(2)} GB</span> — ${x.path}</div>
                    ${(x.children && x.children.length) ? `<ul class="ml-4 list-disc space-y-0.5">${x.children.map(c => `<li class="truncate"><span class="font-mono">${mbToGb(c.size_mb).toFixed(2)} GB</span> — ${c.path}</li>`).join('')}</ul>` : ''}
                    ${(x.top_files && x.top_files.length) ? `<div class="ml-4">
                      <div class="text-xs font-medium mt-1">Top archivos (dir)</div>
                      <ul class="ml-4 space-y-1">
                        ${x.top_files.map(tf => `
                          <li class="space-y-1">
                            <div class="flex items-center justify-between"> 
                              <div class="truncate">
                                <span class="mr-1">${fileEmoji(Math.max(0, Math.min(100, ((tf.size_mb||0) / Math.max(1, x.size_mb||0)) * 100)))}</span>
                                <span class="font-mono">${mbToGb(tf.size_mb).toFixed(2)} GB</span> — ${tf.path}
                              </div>
                              <div class="text-xs text-gray-500">${(Math.max(0, Math.min(100, ((tf.size_mb||0) / Math.max(1, x.size_mb||0)) * 100))).toFixed(1)}%</div>
                            </div>
                            <div class="w-full bg-gray-300 dark:bg-gray-700 rounded h-1.5">
                              <div class="h-1.5 rounded ${fileBarColor(Math.max(0, Math.min(100, ((tf.size_mb||0) / Math.max(1, x.size_mb||0)) * 100)))}" style="width:${Math.max(0, Math.min(100, ((tf.size_mb||0) / Math.max(1, x.size_mb||0)) * 100))}%"></div>
                            </div>
                          </li>
                        `).join('')}
                      </ul>
                    </div>` : ''}
                  </li>
                `).join('')}
              </ul>
            </div>
            <div>
              <div class="font-medium text-sm mb-1">Top archivos del disco</div>
              <ul class="space-y-1">
                ${(d.files||[]).map(f => `<li class="truncate"><span class="font-mono">${mbToGb(f.size_mb).toFixed(2)} GB</span> — ${f.path}</li>`).join('')}
              </ul>
            </div>
          </div>
        `;
        fsHeavy.appendChild(section);
      }
    } catch {}
  }

  async function loadHosts() {
    try {
      const res = await fetch('/api/network/hosts');
      const data = await res.json();
      const hosts = data.hosts || [];
      const procs = data.processes || [];
      tblHosts.innerHTML = hosts.map(h => `<tr class="border-t"><td class="px-2 py-1">${h.host}</td><td class="px-2 py-1 text-right">${h.count}</td><td class="px-2 py-1">${(h.processes||[]).join(', ')}</td></tr>`).join('');
      tblNetProcs.innerHTML = procs.map(p => `<tr class="border-t"><td class="px-2 py-1">${p.process}</td><td class="px-2 py-1">${p.pid ?? ''}</td><td class="px-2 py-1">${(p.hosts||[]).join(', ')}</td></tr>`).join('');
    } catch {}
  }

  function updateDiagUI(s) {
    try {
      const pct = typeof s.progress === 'number' ? Math.max(0, Math.min(100, s.progress)) : null;
      if (pct !== null) {
        diagBar.style.width = `${pct}%`;
      } else if (s.status === 'running') {
        // indeterminado
        const w = parseFloat(diagBar.style.width || '0');
        const next = (isFinite(w) ? ((w + 10) % 100) : 0);
        diagBar.style.width = `${next}%`;
      }
      const stepText = s.step ? ` — ${s.step}` : '';
      diagText.textContent = `Estado: ${s.status || 'idle'}${stepText}`;
      const detail = `rc=${s.last_rc ?? ''}\nSTDOUT:\n${s.last_stdout||''}\n\nSTDERR:\n${s.last_stderr||''}`.trim();
      const hasDetail = !!(s.last_stdout || s.last_stderr);
      if (hasDetail) {
        btnDiagDetail.classList.remove('hidden');
        btnDiagCopy?.classList.remove('hidden');
        diagDetail.textContent = detail;
        lastDiagDetailText = detail;
      }

      // Error callout
      if (diagError && diagErrorMsg) {
        const st = (s.status || '').toLowerCase();
        if (st === 'error' || st === 'failed') {
          const msg = (s.last_stderr || s.error || 'Se produjo un error en el diagnóstico').toString();
          diagErrorMsg.textContent = msg;
          diagError.classList.remove('hidden');
        } else {
          diagError.classList.add('hidden');
          diagErrorMsg.textContent = '';
        }
      }

      // Badge de estado
      if (diagStatusBadge) {
        const base = 'text-xs px-2 py-0.5 rounded ';
        const st = (s.status || 'idle').toLowerCase();
        const map = {
          idle: 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200',
          running: 'bg-blue-100 dark:bg-blue-900/40 text-blue-800 dark:text-blue-200',
          done: 'bg-green-100 dark:bg-green-900/40 text-green-800 dark:text-green-200',
          completed: 'bg-green-100 dark:bg-green-900/40 text-green-800 dark:text-green-200',
          error: 'bg-red-100 dark:bg-red-900/40 text-red-800 dark:text-red-200',
          failed: 'bg-red-100 dark:bg-red-900/40 text-red-800 dark:text-red-200'
        };
        const cls = map[st] || map.idle;
        diagStatusBadge.className = base + cls;
        diagStatusBadge.textContent = st.charAt(0).toUpperCase() + st.slice(1);
      }
    } catch {}
  }

  async function pollDiagStatus() {
    try {
      const res = await fetch('/api/action/diagnostics/status');
      if (!res.ok) return;
      const s = await res.json();
      updateDiagUI(s);
    } catch {}
  }

  function showStatus(msg, type = 'info') {
    statusEl.classList.remove('hidden');
    statusEl.textContent = msg;
    const base = 'px-4 py-2 rounded border text-sm';
    const map = {
      info: 'bg-blue-50 border-blue-200 text-blue-800 dark:bg-blue-900/30 dark:border-blue-800 dark:text-blue-200',
      ok: 'bg-green-50 border-green-200 text-green-800 dark:bg-green-900/30 dark:border-green-800 dark:text-green-200',
      err: 'bg-red-50 border-red-200 text-red-800 dark:bg-red-900/30 dark:border-red-800 dark:text-red-200'
    };
    statusEl.className = `${base} ${map[type] || map.info}`;
  }


  refreshProcMem.addEventListener('click', loadProcMem);
  refreshProcCpu.addEventListener('click', loadProcCpu);
  refreshConns.addEventListener('click', loadConns);
  refreshFsHeavy.addEventListener('click', loadFsHeavy);
  refreshHosts.addEventListener('click', loadHosts);

  // WebSocket realtime metrics con fallback a polling
  let pollTimer = null;
  function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(fetchMetricsOnce, 2000);
    showStatus('Modo fallback por HTTP (WS no disponible).', 'info');
  }

  function connectWS() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws`);
    let opened = false;
    ws.onopen = () => {
      opened = true;
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
      showStatus('Conectado por WebSocket en tiempo real.', 'ok');
    };
    ws.onmessage = ev => {
      const data = JSON.parse(ev.data);
      updateMetrics(data);
      // Marcar recepción reciente para apagar watchdog de polling HTTP
      try { __coreLastEvtTs = Date.now(); } catch {}
      try { window.__owCoreFirstDataReceived = true; } catch {}
      // Emitir evento unificado para que header.js cierre el loader al recibir primer dato (WS)
      try { window.dispatchEvent(new CustomEvent('ow:core:update', { detail: data })); } catch {}
    };
    ws.onerror = () => { if (!opened) startPolling(); };
    ws.onclose = () => { startPolling(); setTimeout(connectWS, 4000); };
  }

  // Initial loads
  fetchMetricsOnce();
  connectWS();
  loadProcMem();
  loadProcCpu();
  loadConns();
  loadFsHeavy();
  loadHosts();
  loadGBProfiles();
  // Sensores: aplicar una vez y luego dejar que el header emita eventos; watchdog activa fallback si no llegan eventos
  loadSensors();
  let __sensorsLastEvtTs = 0;
  let __sensorsTimer = null;
  function __startSensorsPoll(){ if (!__sensorsTimer) { __sensorsTimer = setInterval(loadSensors, 7000); } }
  function __stopSensorsPoll(){ if (__sensorsTimer) { clearInterval(__sensorsTimer); __sensorsTimer = null; } }
  function __sensorsWatchdog(){
    const now = Date.now();
    if (!__sensorsLastEvtTs || (now - __sensorsLastEvtTs) > 12000) {
      __startSensorsPoll();
    } else {
      __stopSensorsPoll();
    }
  }
  setInterval(__sensorsWatchdog, 4000);
  window.addEventListener('ow:sensors:update', ev => {
    try { applySensors((ev && ev.detail) || {}); __sensorsLastEvtTs = Date.now(); } catch {}
  });
  // Consumir el estado desde el header (fuente única) y actualizar UI sin hacer fetch adicional
  // Core metrics: si llegan eventos recientes del header, usamos esos datos y apagamos polling HTTP local
  let __coreLastEvtTs = 0;
  function __stopLocalCorePoll(){ if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }
  function __coreWatchdog(){
    const now = Date.now();
    if (!__coreLastEvtTs || (now - __coreLastEvtTs) > 8000) {
      // Sin eventos recientes del header: asegurar fallback HTTP si WS no está conectado
      startPolling();
    } else {
      // Con eventos recientes del header: apagar polling HTTP local
      __stopLocalCorePoll();
    }
  }
  setInterval(__coreWatchdog, 4000);
  window.addEventListener('ow:core:update', ev => {
    try { updateMetrics((ev && ev.detail) || {}); __coreLastEvtTs = Date.now(); } catch {}
  });
  
  // Diagnóstico: eventos del header + watchdog local cuando no haya eventos recientes
  let __diagLastEvtTs = 0;
  let __diagLocalTimer = null;
  function __startLocalDiagPoll(){ if (!__diagLocalTimer) { __diagLocalTimer = setInterval(pollDiagStatus, 2000); } }
  function __stopLocalDiagPoll(){ if (__diagLocalTimer) { clearInterval(__diagLocalTimer); __diagLocalTimer = null; } }
  function __diagWatchdog(){
    const now = Date.now();
    // Si no hay eventos recientes del header, activar polling local; si vuelven, detenerlo
    if (!__diagLastEvtTs || (now - __diagLastEvtTs) > 8000) {
      __startLocalDiagPoll();
    } else {
      __stopLocalDiagPoll();
    }
  }
  setInterval(__diagWatchdog, 4000);

  window.addEventListener('ow:diagnostics:status', ev => {
    try { updateDiagUI((ev && ev.detail) || {}); __diagLastEvtTs = Date.now(); } catch {}
  });
  // Opcional: cuando inicia, reflejar inmediatamente un estado running y marcar actividad
  window.addEventListener('ow:diagnostics:started', () => { try { updateDiagUI({ status: 'running' }); __diagLastEvtTs = Date.now(); } catch {} });
})();
