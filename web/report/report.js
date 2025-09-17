async function fetchJSON(path) {
  try {
    const res = await fetch(path);
    if (!res.ok) throw new Error(res.statusText);
    return await res.json();
  } catch (e) {
    return null;
  }
}

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  Object.assign(node, props);
  for (const c of children) node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  return node;
}

function tableFrom(items, columns) {
  if (!items || !items.length) return el('div', { className: 'empty', textContent: 'Sin datos' });
  const thead = el('thead', {}, [
    el('tr', {}, columns.map(([key, title]) => el('th', { textContent: title || key })))
  ]);
  const tbody = el('tbody');
  for (const it of items) {
    const tr = el('tr');
    for (const [key] of columns) tr.appendChild(el('td', { textContent: (it[key] ?? '').toString() }));
    tbody.appendChild(tr);
  }
  const table = el('table', {}, [thead, tbody]);
  return table;
}

function setSummary(system) {
  const node = document.querySelector('#summary .content');
  if (!system) return node.appendChild(el('div', { className: 'empty', textContent: 'Sin snapshot' }));
  const items = [];
  if (system.cpu_percent != null) items.push(['CPU', `${system.cpu_percent}%`]);
  if (system.memory_used_percent != null) items.push(['RAM', `${system.memory_used_percent}%`]);
  if (system.disk_used_percent != null) items.push(['Disco', `${system.disk_used_percent}%`]);
  if (system.process_count != null) items.push(['Procesos', `${system.process_count}`]);
  node.appendChild(tableFrom(items.map(([k,v])=>({k,v})), [['k','Métrica'],['v','Valor']]));
}

(async function init() {
  const base = 'artifacts/';
  const system = await fetchJSON(base + 'system_scan.json');
  setSummary(system);

  const procMem = await fetchJSON(base + 'processes_memory.json');
  document.querySelector('#processes-mem .content').appendChild(
    tableFrom(procMem?.items || procMem || [], [['name','Proceso'],['pid','PID'],['memory_mb','Mem MB'],['username','Usuario']])
  );

  const procCpu = await fetchJSON(base + 'processes_cpu.json');
  document.querySelector('#processes-cpu .content').appendChild(
    tableFrom(procCpu?.items || procCpu || [], [['name','Proceso'],['pid','PID'],['cpu_percent','CPU %'],['username','Usuario']])
  );

  const conns = await fetchJSON(base + 'connections.json');
  document.querySelector('#connections .content').appendChild(
    tableFrom(conns?.items || conns || [], [['laddr','Local'],['raddr','Remoto'],['status','Estado'],['process_name','Proceso'],['reputation','Reputación']])
  );

  const autoruns = await fetchJSON(base + 'autoruns.json');
  document.querySelector('#autoruns .content').appendChild(
    tableFrom(autoruns?.items || autoruns || [], [['name','Nombre'],['location','Ubicación'],['path','Ruta']])
  );

  const tasks = await fetchJSON(base + 'tasks.json');
  document.querySelector('#tasks .content').appendChild(
    tableFrom(tasks?.items || tasks || [], [['name','Nombre'],['state','Estado'],['path','Ruta']])
  );

  const services = await fetchJSON(base + 'services.json');
  document.querySelector('#services .content').appendChild(
    tableFrom(services?.items || services || [], [['name','Servicio'],['status','Estado'],['binary_path','Binario']])
  );

  const evSys = await fetchJSON(base + 'events_system.json');
  document.querySelector('#events-system .content').appendChild(
    tableFrom(evSys?.items || evSys || [], [['time','Hora'],['level','Nivel'],['source','Origen'],['message','Mensaje']])
  );

  const evApp = await fetchJSON(base + 'events_application.json');
  document.querySelector('#events-app .content').appendChild(
    tableFrom(evApp?.items || evApp || [], [['time','Hora'],['level','Nivel'],['source','Origen'],['message','Mensaje']])
  );

  const avDown = await fetchJSON(base + 'av_downloads.json');
  document.querySelector('#av-downloads .content').appendChild(
    tableFrom(avDown?.items || avDown || [], [['path','Archivo'],['algo','Algoritmo'],['hash','Hash'],['verdict','Veredicto']])
  );

  const avTemp = await fetchJSON(base + 'av_temp.json');
  document.querySelector('#av-temp .content').appendChild(
    tableFrom(avTemp?.items || avTemp || [], [['path','Archivo'],['algo','Algoritmo'],['hash','Hash'],['verdict','Veredicto']])
  );

  const rkPorts = await fetchJSON(base + 'rootkit_ports.json');
  const rkHidden = await fetchJSON(base + 'rootkit_hidden.json');
  document.querySelector('#rootkit .content').appendChild(
    tableFrom(rkPorts?.items || rkPorts || [], [['laddr','Local'],['raddr','Remoto'],['status','Estado']])
  );
  document.querySelector('#rootkit .content').appendChild(
    tableFrom(rkHidden?.items || rkHidden || [], [['pid','PID'],['name','Nombre'],['note','Nota']])
  );
})();
