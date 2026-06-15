// ---- aba Atividade ao vivo: feed de eventos de segurança ----

function onEvents(list) {
  if (!Array.isArray(list) || !list.length) return;
  events = list.concat(events).slice(0, MAX_FEED);
  renderFeed();
}

const SRC = { process:'Processo', network:'Rede', eventlog:'Windows' };

function renderFeed() {
  document.getElementById('evtBadge').textContent = events.length;
  const host = document.getElementById('feed');
  if (!events.length) { host.innerHTML = '<div class="empty">Nenhum evento recente.</div>'; return; }
  host.innerHTML = events.map(e => {
    const sv = sev(e.severity);
    return `<div class="feed-item">
      <div class="when">${timeStr(e.timestampUtc)}</div>
      <div class="sdot" style="background:${sv.color}"></div>
      <div class="body">
        <div class="t">${esc(e.title)}</div>
        <div class="d">${esc(e.description)}</div>
        <div class="src">${SRC[(e.source||'').toLowerCase()] || esc(e.source)}</div>
      </div>
    </div>`;
  }).join('');
}
