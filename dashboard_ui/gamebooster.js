'use strict';

(() => {
  const statusEl = document.getElementById('status');
  const gbProfile = document.getElementById('gbProfile');
  const gbPolicy = document.getElementById('gbPolicy');
  const gbAuto = document.getElementById('gbAuto');
  const gbPreviewBtn = document.getElementById('gbPreview');
  const gbLoadBtn = document.getElementById('gbLoad');
  const gbClearBtn = document.getElementById('gbClear');
  const gbTable = document.getElementById('tblGB');
  const gbPreviewBox = document.getElementById('gbPreviewBox');
  const gbLog = document.getElementById('gbLog');
  const gbConfirmModal = document.getElementById('gbConfirmModal');
  const gbConfirmMsg = document.getElementById('gbConfirmMsg');
  const gbConfirmOk = document.getElementById('gbConfirmOk');
  const gbConfirmCancel = document.getElementById('gbConfirmCancel');

  let autoTimer = null;

  function showStatus(msg, type = 'info') {
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
  }

  async function postJSON(url, body) {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body||{}) });
    let j = {};
    try { j = await r.json(); } catch {}
    return { ok: r.ok, data: j };
  }

  function fmtBytes(n) {
    const v = Number(n) || 0;
    if (v >= (1<<30)) return (v / (1<<30)).toFixed(2) + ' GB';
    if (v >= (1<<20)) return (v / (1<<20)).toFixed(1) + ' MB';
    if (v >= (1<<10)) return (v / (1<<10)).toFixed(0) + ' KB';
    return v + ' B';
  }

  async function confirmAction(message) {
    return new Promise(resolve => {
      if (!gbConfirmModal || !gbConfirmMsg || !gbConfirmOk || !gbConfirmCancel) return resolve(false);
      gbConfirmMsg.textContent = message;
      gbConfirmModal.classList.remove('hidden');
      const onOk = () => { cleanup(); resolve(true); };
      const onCancel = () => { cleanup(); resolve(false); };
      function cleanup() {
        gbConfirmOk.removeEventListener('click', onOk);
        gbConfirmCancel.removeEventListener('click', onCancel);
        gbConfirmModal.classList.add('hidden');
      }
      gbConfirmOk.addEventListener('click', onOk);
      gbConfirmCancel.addEventListener('click', onCancel);
    });
  }

  async function loadProfiles() {
    if (!gbProfile) return;
    try {
      const r = await fetch('/api/profiles');
      if (!r.ok) return;
      const j = await r.json();
      const arr = Array.isArray(j.profiles) ? j.profiles : [];
      gbProfile.innerHTML = arr.map(p => `<option value="${p.name}">${p.name} (${p.actions_count||0})</option>`).join('');
    } catch {}
  }

  async function previewProfile() {
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

  async function loadCandidates() {
    if (!gbTable) return;
    try {
      const r = await fetch('/api/gamebooster/candidates?limit=15');
      const j = await r.json();
      const items = Array.isArray(j.candidates) ? j.candidates : [];
      gbTable.innerHTML = items.map(p => `
        <tr class="border-t">
          <td class="px-2 py-1">${p.pid}</td>
          <td class="px-2 py-1">${p.name||''}<div class="text-xs text-gray-500">${p.reason||''}</div></td>
          <td class="px-2 py-1 text-right">${fmtBytes(p.memory_rss||0)}</td>
          <td class="px-2 py-1 text-right">${(p.cpu_percent??'').toString()}</td>
          <td class="px-2 py-1">
            <div class="flex gap-1">
              <button class="gb-action text-xs text-red-600" data-act="kill" data-pid="${p.pid}" data-name="${p.name||''}">Kill</button>
              <button class="gb-action text-xs text-yellow-600" data-act="isolate" data-pid="${p.pid}" data-name="${p.name||''}">Isolate</button>
              <button class="gb-action text-xs text-gray-700" data-act="unsandbox" data-pid="${p.pid}" data-name="${p.name||''}">Unsandbox</button>
            </div>
          </td>
        </tr>
      `).join('');
    } catch {}
  }

  function log(msg) {
    if (!gbLog) return;
    const ts = new Date().toLocaleTimeString();
    gbLog.textContent = `[${ts}] ${msg}\n` + gbLog.textContent;
  }

  async function doAction(act, pid, name) {
    const policy = gbPolicy?.value || 'Strict';
    let url = '';
    let body = {};
    if (act === 'kill') {
      url = '/api/process/kill';
      body = { pid, policy_name: policy, confirm: true };
    } else if (act === 'isolate') {
      url = '/api/process/isolate';
      body = { pid, policy_name: policy, confirm: true };
    } else if (act === 'unsandbox') {
      url = '/api/process/unsandbox';
      body = { pid, confirm: true };
    } else {
      return;
    }
    const ok = await confirmAction(`¿Confirmas ${act} sobre PID ${pid} (${name||'?'}) con política ${policy}?`);
    if (!ok) return; 

    try {
      const res = await postJSON(url, body);
      if (res?.data?.ok) {
        showStatus(`Acción ${act} ejecutada sobre PID ${pid}.`, 'ok');
        log(`✔ ${act} PID ${pid} (${name||''}) [${policy}]`);
        await loadCandidates();
      } else {
        const err = (res && res.data && (res.data.error || res.data.message)) || 'Fallo en acción';
        showStatus(`Error en ${act}: ${err}`, 'err');
        log(`✖ Error en ${act} PID ${pid}: ${err}`);
      }
    } catch (e) {
      showStatus(`Error ejecutando ${act}.`, 'err');
      log(`✖ Excepción en ${act} PID ${pid}`);
    }
  }

  gbPreviewBtn?.addEventListener('click', previewProfile);
  gbLoadBtn?.addEventListener('click', loadCandidates);
  gbClearBtn?.addEventListener('click', () => {
    if (gbPreviewBox) { gbPreviewBox.classList.add('hidden'); gbPreviewBox.textContent = ''; }
    if (gbTable) gbTable.innerHTML = '';
    if (gbLog) gbLog.textContent = '';
  });

  gbTable?.addEventListener('click', async (ev) => {
    const t = ev.target;
    if (!(t instanceof HTMLElement)) return;
    const btn = t.closest('button.gb-action');
    if (!btn) return;
    const act = btn.getAttribute('data-act');
    const pid = parseInt(btn.getAttribute('data-pid')||'0', 10);
    const name = btn.getAttribute('data-name')||'';
    if (!pid || !act) return;
    await doAction(act, pid, name);
  });

  gbAuto?.addEventListener('change', () => {
    if (gbAuto.checked) {
      if (!autoTimer) autoTimer = setInterval(loadCandidates, 5000);
    } else {
      if (autoTimer) { clearInterval(autoTimer); autoTimer = null; }
    }
  });

  // Initial load
  loadProfiles();
  loadCandidates();
})();
