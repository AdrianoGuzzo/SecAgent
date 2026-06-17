// ---- aba Resumo: banner de status, progresso, achados e incidente ----

class ResumoPanel {
  // Mapa de aparência do banner por severidade agregada: [título, subtítulo, cor do ponto].
  static BANNER = {
    green:  ['Tudo sob controle', 'Nenhum problema sério detectado.', '#22c55e'],
    yellow: ['Pontos de atenção', 'Há itens que merecem sua atenção.', '#eab308'],
    red:    ['Atenção necessária', 'Foram encontrados problemas importantes.', '#ef4444'],
    gray:   ['Aguardando dados…', 'Conectando ao serviço SecAgent.', '#64748b']
  };

  static RANK = { critical: 4, high: 3, medium: 2, low: 1 };

  register(router) {
    router.registerAll({
      status:      s => this.onStatus(s),
      tokenStatus: p => this.onTokenStatus(p),
      progress:    p => this.onProgress(p),
      report:      r => this.onReport(r),
      incident:    i => this.onIncident(i)
    });
  }

  // ---- status banner ----
  onStatus(s) {
    if (!s) return;
    const sevOverall = (s.overallSeverity || 'gray').toLowerCase();
    const key = ['red', 'yellow', 'green'].includes(sevOverall) ? sevOverall : 'gray';
    const b = document.getElementById('banner');
    b.className = 'banner ' + key;
    const [title, sub, color] = ResumoPanel.BANNER[key];
    b.querySelector('.dot').style.background = color;
    document.getElementById('bannerTitle').textContent = title;
    document.getElementById('bannerSub').textContent = sub;

    if (s.lastScan) {
      const t = Format.time(s.lastScan.timestampUtc);
      document.getElementById('lastScan').textContent =
        `Última análise: ${t} · ${s.lastScan.findingsCount || 0} achado(s)`;
    }
  }

  // ---- token status (botão de IA vs. configurar) ----
  onTokenStatus(p) {
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
  onProgress(p) {
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
  onReport(r) {
    if (!r) return;
    if (r.summary) {
      document.getElementById('summaryBox').style.display = 'block';
      document.getElementById('summaryText').textContent = r.summary;
    }
    this._renderFindings(r.findings || []);
  }

  _renderFindings(findings) {
    const host = document.getElementById('findings');
    const fs = findings.slice().sort((a, b) => this._rank(b.severity) - this._rank(a.severity));
    if (!fs.length) {
      host.innerHTML = '<div class="empty">Nenhum achado na última análise. 👍</div>';
      return;
    }
    host.innerHTML = fs.map(f => {
      const sv = Severity.of(f.severity);
      return `<div class="card sev-${sv.cls}">
        <div class="head">
          <span class="pill ${sv.cls}">${sv.label}</span>
          <span class="cat">${Format.esc(f.category || '')}</span>
        </div>
        <h4>${Format.esc(f.title)}</h4>
        <div class="desc">${Format.esc(f.description)}</div>
        ${f.recommendation ? `<div class="rec"><b>O que fazer:</b> ${Format.esc(f.recommendation)}</div>` : ''}
      </div>`;
    }).join('');
  }

  _rank(s) { return ResumoPanel.RANK[(s || '').toLowerCase()] || 0; }

  // ---- incident ----
  onIncident(i) {
    if (!i) return;
    this._renderIncident(i);
  }

  _renderIncident(i) {
    const sv = Severity.of(i.severity);
    const acts = (i.recommendedActions || []).map(a => `<li>${Format.esc(a)}</li>`).join('');
    document.getElementById('incidentBox').innerHTML =
      `<div class="card sev-${sv.cls}">
        <div class="head">
          <span class="pill ${sv.cls}">${sv.label}</span>
          <span class="cat">Incidente · ${Format.time(i.timestampUtc)} · ${i.eventCount || 0} evento(s)</span>
        </div>
        <h4>${Format.esc(i.title)}</h4>
        <div class="desc">${Format.esc(i.summary)}</div>
        ${acts ? `<div class="rec"><b>Ações recomendadas:</b><ul style="margin:6px 0 0">${acts}</ul></div>` : ''}
      </div>`;
  }
}

new ResumoPanel().register(SecAgent.router);
