// ---- aba Tráfego por IP: mede quanto cada IP transferiu num período (play/stop) ----
// A acumulação roda no Service (sobrevive ao fechar o painel); esta aba só dispara
// play/stop (cmd) e renderiza o traffic-track.json que o Service grava a ~0,5s.

class TrafegoIpPanel {
  constructor() {
    // Ordenação padrão: maior Total primeiro (quem mais consumiu banda no topo).
    this._sort = { key: 'total', dir: -1 };
    this._last = null;             // último snapshot recebido
    this._blockedIps = new Set();  // IPs já bloqueados (vem por delegação do ConexoesPanel)

    this._bindSortHeaders();
    this._bindBlockClicks();
  }

  register(router) {
    router.register('trafficTrack', snap => this.onTrafficTrack(snap));
  }

  // ---- handlers ----
  onTrafficTrack(snap) {
    this._last = snap || null;
    this._renderStatus();
    this._render();
  }

  // Recebe o conjunto de IPs bloqueados (delegado pelo ConexoesPanel, dono do
  // tipo 'blocked'); apenas re-renderiza para marcar/desmarcar o 🚫.
  onBlocked(blockedIps) {
    this._blockedIps = (blockedIps instanceof Set) ? blockedIps : new Set();
    this._render();
  }

  // ---- DOM wiring ----
  _bindSortHeaders() {
    document.querySelectorAll('#trafego-ip th[data-sort-key]').forEach(th => {
      th.classList.add('sortable');
      th.onclick = () => {
        const key = th.dataset.sortKey;
        if (this._sort.key === key) this._sort.dir = -this._sort.dir;
        else this._sort = { key, dir: (key === 'ip' || key === 'process') ? 1 : -1 };
        this._render();
      };
    });
  }

  // Delegação de clique para bloquear o IP (reusa o comando blockIp: do Service).
  _bindBlockClicks() {
    document.getElementById('trafipRows').addEventListener('click', e => {
      const btn = e.target.closest('button.cut');
      if (!btn || !btn.dataset.ip) return;
      const ip = btn.dataset.ip;
      if (confirm('Bloquear ' + ip + ' (entrada e saída)?\n\nIsso cria regras no Firewall do Windows. A conexão atual pode levar alguns segundos para cair.')) {
        this._blockedIps.add(ip);   // feedback otimista; blocked.json confirma em ~1-2s
        this._render();
        cmd('blockIp:' + ip);
      }
    });
  }

  // ---- status (barra play/stop) ----
  _renderStatus() {
    const start = document.getElementById('btnTrafipStart');
    const stop = document.getElementById('btnTrafipStop');
    const status = document.getElementById('trafipStatus');
    const snap = this._last;

    const active = !!(snap && snap.active);
    start.style.display = active ? 'none' : '';
    stop.style.display = active ? '' : 'none';

    if (!snap || (!snap.active && !snap.startedUtc)) {
      status.textContent = 'Medição parada.';
      return;
    }
    const secs = Math.max(0, Math.round(Number(snap.elapsedSeconds) || 0));
    const n = (snap.totals || []).length;
    if (snap.active) {
      status.textContent = `Medindo há ${this._dur(secs)} · ${n} IP(s).`;
    } else {
      status.textContent = `Período medido: ${this._dur(secs)} · ${n} IP(s) · encerrado às ${Format.time(snap.stoppedUtc)}.`;
    }
  }

  // segundos -> "Xs" / "Xm Ys" / "Xh Ym"
  _dur(s) {
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
    return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
  }

  // ---- tabela ----
  _sortRows(rows) {
    const { key, dir } = this._sort;
    return rows.sort((a, b) => {
      const av = a[key], bv = b[key];
      const cmp = (key === 'ip' || key === 'process')
        ? String(av).localeCompare(String(bv), 'pt-BR', { sensitivity: 'base' })
        : av - bv;
      return cmp * dir;
    });
  }

  _updateArrows() {
    document.querySelectorAll('#trafego-ip th[data-sort-key]').forEach(th => {
      const arrow = th.querySelector('.arrow');
      if (!arrow) return;
      arrow.textContent = (this._sort.key === th.dataset.sortKey)
        ? (this._sort.dir === 1 ? '▲' : '▼') : '';
    });
  }

  _render() {
    const totals = (this._last && this._last.totals) || [];
    document.getElementById('trafipBadge').textContent = totals.length;
    const tbody = document.getElementById('trafipRows');
    const empty = document.getElementById('trafipEmpty');
    this._updateArrows();

    if (!totals.length) { tbody.innerHTML = ''; empty.style.display = 'block'; return; }
    empty.style.display = 'none';

    const rows = this._sortRows(totals.map(t => ({
      ip: t.ip || '',
      process: t.processName || 'desconhecido',
      in: Number(t.bytesIn) || 0,
      out: Number(t.bytesOut) || 0,
      total: Number(t.bytesTotal) || 0
    })));

    tbody.innerHTML = rows.map(r => {
      const isBlocked = this._blockedIps.has(r.ip);
      const cut = isBlocked
        ? `<span class="cut blocked" title="IP bloqueado">🚫</span>`
        : `<button class="cut" data-ip="${Format.esc(r.ip)}" title="Bloquear este IP (entrada e saída)">✕</button>`;
      return `<tr class="${isBlocked ? 'blocked' : ''}">
        <td class="mono">${cut}${Format.esc(r.ip)}</td>
        <td>${Format.esc(r.process)}</td>
        <td class="mono">${Format.bytes(r.in)}</td>
        <td class="mono">${Format.bytes(r.out)}</td>
        <td class="mono"><b>${Format.bytes(r.total)}</b></td>
      </tr>`;
    }).join('');
  }
}

// Bootstrap: exposto como SecAgent.trafegoIp para o ConexoesPanel delegar 'blocked'.
SecAgent.trafegoIp = new TrafegoIpPanel();
SecAgent.trafegoIp.register(SecAgent.router);
