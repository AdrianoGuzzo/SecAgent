// ---- aba Conexões de rede: tabela de IPs com ordenação por coluna ----

class ConexoesPanel {
  // Limiares de cor do tráfego (bytes/s). Ajuste aqui se quiser ser mais/menos sensível.
  static RATE_MID = 50 * 1024;        // >= 50 KB/s  => médio (amarelo)
  static RATE_HIGH = 1024 * 1024;     // >= 1 MB/s   => alto  (vermelho)

  constructor() {
    // _connSort.key === null => ordem padrão (entrada antes de saída).
    // Caso contrário ordena pela coluna escolhida; dir 1 = asc, -1 = desc.
    this._connSort = { key: null, dir: 1 };
    // IPs atualmente bloqueados (regras de firewall criadas pelo Service).
    this._blockedIps = new Set();
    // Snapshot atual de conexões e cache de geolocalização por IP público.
    this._lastNetwork = null;
    this._geoMap = {};

    this._bindSortHeaders();
    this._bindBlockClicks();
  }

  register(router) {
    router.registerAll({
      network: snap => this.onNetwork(snap),
      geo:     g => this.onGeo(g),
      blocked: p => this.onBlocked(p)
    });
  }

  // ---- handlers ----
  onNetwork(snap) {
    this._lastNetwork = snap;
    this._renderConns();
    // Atualiza o widget de tráfego total (card no Resumo + chip aqui).
    SecAgent.trafego?.render(snap.interfaces || []);
  }

  onGeo(g) {
    if (!g || !g.ip) return;
    this._geoMap[g.ip] = g.geo;
    this._renderConns();
  }

  onBlocked(p) {
    const d = (typeof p === 'string') ? JSON.parse(p) : p;
    this._blockedIps = new Set(((d && d.blocked) || []).map(b => b.ip));
    this._renderConns();
    this._renderBlocked();
    // O roteador só permite um handler por tipo e este é o dono de 'blocked';
    // a aba Tráfego por IP precisa do mesmo conjunto p/ marcar IPs já bloqueados.
    SecAgent.trafegoIp?.onBlocked(this._blockedIps);
  }

  // ---- DOM wiring ----
  // Liga o clique nos cabeçalhos ordenáveis (mesma key alterna direção;
  // nova key começa ascendente).
  _bindSortHeaders() {
    document.querySelectorAll('#conexoes th[data-sort-key]').forEach(th => {
      th.classList.add('sortable');
      th.onclick = () => {
        const key = th.dataset.sortKey;
        if (this._connSort.key === key) this._connSort.dir = -this._connSort.dir;
        else this._connSort = { key, dir: 1 };
        this._renderConns();
      };
    });
  }

  // Delegação de cliques (registrada uma vez) para bloquear/desbloquear.
  _bindBlockClicks() {
    document.getElementById('connRows').addEventListener('click', e => {
      const btn = e.target.closest('button.cut');
      if (!btn || !btn.dataset.ip) return;
      const ip = btn.dataset.ip;
      if (confirm('Bloquear ' + ip + ' (entrada e saída)?\n\nIsso cria regras no Firewall do Windows. A conexão atual pode levar alguns segundos para cair.')) {
        this._blockedIps.add(ip);   // feedback otimista; blocked.json confirma em ~1-2s
        this._renderConns();
        cmd('blockIp:' + ip);
      }
    });
    document.getElementById('blockedBox').addEventListener('click', e => {
      const btn = e.target.closest('button.unblock');
      if (!btn || !btn.dataset.ip) return;
      const ip = btn.dataset.ip;
      this._blockedIps.delete(ip);  // feedback otimista
      this._renderConns();
      this._renderBlocked();
      cmd('unblockIp:' + ip);
    });
  }

  // ---- formatação de tráfego ----
  _rateLevel(bps) {
    if (bps >= ConexoesPanel.RATE_HIGH) return 'high';
    if (bps >= ConexoesPanel.RATE_MID) return 'mid';
    return 'low';
  }

  // ---- modelo + ordenação ----
  // Converte uma conexão crua no modelo normalizado usado para render + ordenação.
  _normalize(c) {
    const inbound = c.direction === 'inbound';
    let localText = 'Rede local', localHtml = '<span class="muted">Rede local</span>';
    let ispText = '—', ispHtml = '<span class="muted">—</span>';
    if (c.remoteIsPublic) {
      const g = this._geoMap[c.remoteAddress];
      if (g) {
        localText = `${g.country || ''}${g.city ? ' · ' + g.city : ''}`.trim();
        localHtml = `${Format.flag(g.countryCode)} ${Format.esc(g.country)}${g.city ? ' · ' + Format.esc(g.city) : ''}`;
        ispText = g.isp || '—';
        ispHtml = Format.esc(g.isp || '—');
      } else {
        localText = 'carregando…'; localHtml = '<span class="muted">carregando…</span>';
        ispText = '…'; ispHtml = '<span class="muted">…</span>';
      }
    }
    const bps = Number(c.bytesPerSec) || 0;
    return {
      inbound, remoteIsPublic: c.remoteIsPublic,
      localHtml, ispHtml,
      rateText: Format.rate(bps), rateLevel: this._rateLevel(bps),
      sort: {
        dir: inbound ? 0 : 1,
        process: c.processName || '',
        rate: bps,
        remote: c.remoteAddress || '',
        local: localText,
        isp: ispText,
        port: Number(c.remotePort) || 0
      },
      processName: c.processName, remoteAddress: c.remoteAddress, remotePort: c.remotePort
    };
  }

  _sortRows(rows) {
    const { key, dir } = this._connSort;
    if (!key) {
      // Padrão: entrada antes de saída (sem reordenar o resto).
      return rows.sort((a, b) => a.sort.dir - b.sort.dir);
    }
    return rows.sort((a, b) => {
      const av = a.sort[key], bv = b.sort[key];
      const cmp = (key === 'port' || key === 'dir' || key === 'rate')
        ? av - bv
        : String(av).localeCompare(String(bv), 'pt-BR', { sensitivity: 'base' });
      return cmp * dir;
    });
  }

  _updateArrows() {
    document.querySelectorAll('#conexoes th[data-sort-key]').forEach(th => {
      const arrow = th.querySelector('.arrow');
      if (!arrow) return;
      arrow.textContent = (this._connSort.key === th.dataset.sortKey)
        ? (this._connSort.dir === 1 ? '▲' : '▼') : '';
    });
  }

  // ---- render ----
  _renderConns() {
    const conns = (this._lastNetwork && this._lastNetwork.connections) || [];
    document.getElementById('connBadge').textContent = conns.length;
    const tbody = document.getElementById('connRows');
    const empty = document.getElementById('connEmpty');
    this._updateArrows();
    if (!conns.length) { tbody.innerHTML = ''; empty.style.display = 'block'; return; }
    empty.style.display = 'none';

    const rows = this._sortRows(conns.map(c => this._normalize(c)));

    tbody.innerHTML = rows.map(r => {
      const isBlocked = this._blockedIps.has(r.remoteAddress);
      const cls = (r.inbound && r.remoteIsPublic ? 'inbound' : '') + (isBlocked ? ' blocked' : '');
      const cut = isBlocked
        ? `<span class="cut blocked" title="IP bloqueado">🚫</span>`
        : `<button class="cut" data-ip="${Format.esc(r.remoteAddress)}" title="Bloquear este IP (entrada e saída)">✕</button>`;
      return `<tr class="${cls.trim()}">
        <td class="dir ${r.inbound ? 'in' : 'out'}">${r.inbound ? '↓ Entrada' : '↑ Saída'}</td>
        <td>${Format.esc(r.processName)}</td>
        <td class="rate rate-${r.rateLevel} mono">${r.rateText}</td>
        <td class="mono">${cut}${Format.esc(r.remoteAddress)}</td>
        <td>${r.localHtml}</td>
        <td>${r.ispHtml}</td>
        <td class="mono">${r.remotePort}</td>
      </tr>`;
    }).join('');
  }

  // Segunda tabela "Conexões bloqueadas": IPs com regra de firewall ativa.
  _renderBlocked() {
    const box = document.getElementById('blockedBox');
    const tbody = document.getElementById('blockedRows');
    if (!box || !tbody) return;
    const ips = [...this._blockedIps];
    document.getElementById('blockedBadge').textContent = ips.length;
    if (!ips.length) { box.style.display = 'none'; tbody.innerHTML = ''; return; }
    box.style.display = 'block';
    tbody.innerHTML = ips.map(ip =>
      `<tr>
        <td class="mono">${Format.esc(ip)}</td>
        <td><button class="unblock" data-ip="${Format.esc(ip)}">Desbloquear</button></td>
      </tr>`).join('');
  }
}

new ConexoesPanel().register(SecAgent.router);
