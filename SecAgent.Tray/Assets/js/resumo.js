// ---- aba Resumo: banner de status, progresso, achados e incidente ----

// ---- status banner ----
function onStatus(s) {
  if (!s) return;
  const sevOverall = (s.overallSeverity || 'gray').toLowerCase();
  const b = document.getElementById('banner');
  b.className = 'banner ' + (['red','yellow','green'].includes(sevOverall) ? sevOverall : 'gray');
  const map = {
    green:  ['Tudo sob controle', 'Nenhum problema sério detectado.', '#22c55e'],
    yellow: ['Pontos de atenção', 'Há itens que merecem sua atenção.', '#eab308'],
    red:    ['Atenção necessária', 'Foram encontrados problemas importantes.', '#ef4444'],
    gray:   ['Aguardando dados…', 'Conectando ao serviço SecAgent.', '#64748b']
  };
  const m = map[b.classList.contains('red')?'red':b.classList.contains('yellow')?'yellow':b.classList.contains('green')?'green':'gray'];
  b.querySelector('.dot').style.background = m[2];
  document.getElementById('bannerTitle').textContent = m[0];
  document.getElementById('bannerSub').textContent = m[1];

  if (s.lastScan) {
    const t = timeStr(s.lastScan.timestampUtc);
    document.getElementById('lastScan').textContent =
      `Última análise: ${t} · ${s.lastScan.findingsCount || 0} achado(s)`;
  }
}

// ---- token status (botão de IA vs. configurar) ----
function onTokenStatus(p) {
  const configured = !!(p && p.configured);
  const analyze = document.getElementById('btnAnalyze');
  const config = document.getElementById('btnConfigAI');
  if (analyze) {
    analyze.style.display = configured ? '' : 'none';
    analyze.disabled = !configured;
  }
  if (config) config.style.display = configured ? 'none' : '';
}

// ---- progress ----
function onProgress(p) {
  const box = document.getElementById('progress');
  if (!p) { box.style.display = 'none'; return; }
  box.style.display = 'block';
  const label = p.state === 'analyzing'
    ? 'Analisando com inteligência artificial…'
    : 'Verificando o sistema…';
  document.getElementById('progressLabel').textContent =
    (p.step ? p.step + ' — ' : '') + label;
}

// ---- report (findings) ----
function onReport(r) {
  if (!r) return;
  if (r.summary) {
    document.getElementById('summaryBox').style.display = 'block';
    document.getElementById('summaryText').textContent = r.summary;
  }
  const host = document.getElementById('findings');
  const fs = (r.findings || []).slice().sort((a,b) => rank(b.severity) - rank(a.severity));
  if (!fs.length) { host.innerHTML = '<div class="empty">Nenhum achado na última análise. 👍</div>'; return; }
  host.innerHTML = fs.map(f => {
    const sv = sev(f.severity);
    return `<div class="card sev-${sv.cls}">
      <div class="head">
        <span class="pill ${sv.cls}">${sv.label}</span>
        <span class="cat">${esc(f.category || '')}</span>
      </div>
      <h4>${esc(f.title)}</h4>
      <div class="desc">${esc(f.description)}</div>
      ${f.recommendation ? `<div class="rec"><b>O que fazer:</b> ${esc(f.recommendation)}</div>` : ''}
    </div>`;
  }).join('');
}
function rank(s) { return {critical:4,high:3,medium:2,low:1}[(s||'').toLowerCase()] || 0; }

// ---- incident ----
function onIncident(i) {
  if (!i) return;
  const sv = sev(i.severity);
  const acts = (i.recommendedActions || []).map(a => `<li>${esc(a)}</li>`).join('');
  document.getElementById('incidentBox').innerHTML =
    `<div class="card sev-${sv.cls}">
      <div class="head">
        <span class="pill ${sv.cls}">${sv.label}</span>
        <span class="cat">Incidente · ${timeStr(i.timestampUtc)} · ${i.eventCount||0} evento(s)</span>
      </div>
      <h4>${esc(i.title)}</h4>
      <div class="desc">${esc(i.summary)}</div>
      ${acts ? `<div class="rec"><b>Ações recomendadas:</b><ul style="margin:6px 0 0">${acts}</ul></div>` : ''}
    </div>`;
}
