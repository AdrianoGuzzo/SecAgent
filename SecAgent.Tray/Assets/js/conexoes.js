// ---- aba Conexões de rede: tabela de IPs com ordenação por coluna ----

// connSort.key === null => ordem padrão (entrada antes de saída).
// Caso contrário ordena pela coluna escolhida; dir 1 = asc, -1 = desc.
let connSort = { key: null, dir: 1 };

function onNetwork(snap) {
  lastNetwork = snap;
  renderConns();
}
function onGeo(g) {
  if (!g || !g.ip) return;
  geoMap[g.ip] = g.geo;
  renderConns();
}

// Liga o clique nos cabeçalhos ordenáveis (mesma key alterna direção;
// nova key começa ascendente).
document.querySelectorAll('#conexoes th[data-sort-key]').forEach(th => {
  th.classList.add('sortable');
  th.onclick = () => {
    const key = th.dataset.sortKey;
    if (connSort.key === key) connSort.dir = -connSort.dir;
    else connSort = { key, dir: 1 };
    renderConns();
  };
});

function updateSortArrows() {
  document.querySelectorAll('#conexoes th[data-sort-key]').forEach(th => {
    const arrow = th.querySelector('.arrow');
    if (!arrow) return;
    arrow.textContent = (connSort.key === th.dataset.sortKey)
      ? (connSort.dir === 1 ? '▲' : '▼') : '';
  });
}

// Converte uma conexão crua no modelo normalizado usado para render + ordenação.
function normalizeConn(c) {
  const inbound = c.direction === 'inbound';
  let localText = 'Rede local', localHtml = '<span class="muted">Rede local</span>';
  let ispText = '—', ispHtml = '<span class="muted">—</span>';
  if (c.remoteIsPublic) {
    const g = geoMap[c.remoteAddress];
    if (g) {
      localText = `${g.country || ''}${g.city ? ' · ' + g.city : ''}`.trim();
      localHtml = `${flag(g.countryCode)} ${esc(g.country)}${g.city ? ' · ' + esc(g.city) : ''}`;
      ispText = g.isp || '—';
      ispHtml = esc(g.isp || '—');
    } else {
      localText = 'carregando…'; localHtml = '<span class="muted">carregando…</span>';
      ispText = '…'; ispHtml = '<span class="muted">…</span>';
    }
  }
  return {
    inbound, remoteIsPublic: c.remoteIsPublic,
    localHtml, ispHtml,
    sort: {
      dir: inbound ? 0 : 1,
      process: c.processName || '',
      remote: c.remoteAddress || '',
      local: localText,
      isp: ispText,
      port: Number(c.remotePort) || 0
    },
    processName: c.processName, remoteAddress: c.remoteAddress, remotePort: c.remotePort
  };
}

function sortRows(rows) {
  if (!connSort.key) {
    // Padrão: entrada antes de saída (sem reordenar o resto).
    return rows.sort((a, b) => a.sort.dir - b.sort.dir);
  }
  const k = connSort.key;
  return rows.sort((a, b) => {
    const av = a.sort[k], bv = b.sort[k];
    let cmp;
    if (k === 'port' || k === 'dir') cmp = av - bv;
    else cmp = String(av).localeCompare(String(bv), 'pt-BR', { sensitivity: 'base' });
    return cmp * connSort.dir;
  });
}

function renderConns() {
  const conns = (lastNetwork && lastNetwork.connections) || [];
  document.getElementById('connBadge').textContent = conns.length;
  const tbody = document.getElementById('connRows');
  const empty = document.getElementById('connEmpty');
  updateSortArrows();
  if (!conns.length) { tbody.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';

  const rows = sortRows(conns.map(normalizeConn));

  tbody.innerHTML = rows.map(r => {
    return `<tr class="${r.inbound && r.remoteIsPublic ? 'inbound' : ''}">
      <td class="dir ${r.inbound?'in':'out'}">${r.inbound?'↓ Entrada':'↑ Saída'}</td>
      <td>${esc(r.processName)}</td>
      <td class="mono">${esc(r.remoteAddress)}</td>
      <td>${r.localHtml}</td>
      <td>${r.ispHtml}</td>
      <td class="mono">${r.remotePort}</td>
    </tr>`;
  }).join('');
}
