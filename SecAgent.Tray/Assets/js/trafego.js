// ---- widget de tráfego total: soma de todas as interfaces físicas ----
// Mostra o total agregado (↓ download · ↑ upload) em dois pontos do painel
// (card no Resumo + chip nas Conexões); o tooltip nativo detalha cada interface.
//
// NÃO registra um handler 'network' próprio: o roteador só permite um handler
// por tipo (core.js), e a aba Conexões já é dona desse tipo. Ela delega aqui
// via SecAgent.trafego.render(...) a cada snapshot.

class TrafegoPanel {
  constructor() {
    // Elementos-alvo (podem não existir se o HTML mudar — guardamos com ?.).
    this._resumo = document.getElementById('trafficTotalResumo');
    this._conex = document.getElementById('trafficTotalConex');
    this._cardResumo = document.getElementById('trafficCard');
    this._chipConex = document.getElementById('trafficTotalConex');
  }

  // Recebe a lista de interfaces do snapshot e atualiza total + tooltip.
  render(ifaces) {
    const list = Array.isArray(ifaces) ? ifaces : [];
    const down = list.reduce((s, i) => s + (Number(i.bytesDownPerSec) || 0), 0);
    const up = list.reduce((s, i) => s + (Number(i.bytesUpPerSec) || 0), 0);

    const totalText = `↓ ${Format.rate(down)} · ↑ ${Format.rate(up)}`;
    if (this._resumo) this._resumo.textContent = totalText;
    if (this._conex) this._conex.textContent = `Tráfego total ${totalText}`;

    // Tooltip nativo: uma linha por interface (quebra com \n).
    const tip = list.length
      ? list.map(i => `${i.name}:  ↓ ${Format.rate(i.bytesDownPerSec)}  ↑ ${Format.rate(i.bytesUpPerSec)}`).join('\n')
      : 'Nenhuma interface física ativa detectada.';
    if (this._cardResumo) this._cardResumo.title = tip;
    if (this._chipConex) this._chipConex.title = tip;
  }
}

SecAgent.trafego = new TrafegoPanel();
