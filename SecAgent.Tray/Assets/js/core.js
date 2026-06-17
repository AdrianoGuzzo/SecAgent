// ---- core: infraestrutura compartilhada (namespace, helpers, bridge, roteador, abas) ----

// Namespace único exposto às demais abas (resumo/conexoes/eventos), carregadas depois.
const SecAgent = window.SecAgent = {};

// ---- severidade ----
// Mapeia a severidade textual em rótulo/classe CSS/cor usados pelos cards e feed.
class Severity {
  static MAP = {
    critical: { label: 'CRÍTICO', cls: 'critical', color: '#b91c1c' },
    high:     { label: 'ALTO',    cls: 'high',     color: '#ef4444' },
    medium:   { label: 'MÉDIO',   cls: 'medium',   color: '#f59e0b' },
    low:      { label: 'BAIXO',   cls: 'low',      color: '#ca8a04' },
    info:     { label: 'INFO',    cls: 'info',     color: '#64748b' }
  };

  static of(s) { return Severity.MAP[(s || 'info').toLowerCase()] || Severity.MAP.info; }
}

// ---- formatação genérica ----
class Format {
  // Escapa HTML para prevenir XSS ao injetar texto vindo do Service via innerHTML.
  static esc(s) {
    return (s == null ? '' : String(s))
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // Código de país de 2 letras -> emoji de bandeira (ex.: "BR" -> 🇧🇷).
  static flag(cc) {
    if (!cc || cc.length !== 2) return '🌐';
    const A = 0x1F1E6;
    return String.fromCodePoint(A + cc.charCodeAt(0) - 65, A + cc.charCodeAt(1) - 65);
  }

  // ISO timestamp -> "HH:mm:ss" em pt-BR; string vazia se inválido.
  static time(iso) {
    try { return new Date(iso).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
    catch (e) { return ''; }
  }

  // bytes/s -> texto amigável (—, KB/s, MB/s) com locale pt-BR. Usado tanto na
  // coluna de tráfego por conexão quanto no total agregado por interface.
  static rate(bps) {
    if (!bps || bps < 1024) return '—';
    if (bps < 1024 * 1024) return (bps / 1024).toLocaleString('pt-BR', { maximumFractionDigits: 0 }) + ' KB/s';
    return (bps / (1024 * 1024)).toLocaleString('pt-BR', { maximumFractionDigits: 1 }) + ' MB/s';
  }
}

// ---- ponte com o host C# (WebView2) ----
// Encapsula window.chrome.webview: enviar comandos e assinar mensagens.
class Bridge {
  // Envia um comando para o host (botões de scan, block/unblock de IP, etc.).
  send(cmd) {
    try { window.chrome.webview.postMessage({ cmd }); } catch (e) {}
  }

  // Registra um callback que recebe o payload bruto de cada mensagem do host.
  onMessage(handler) {
    window.chrome.webview.addEventListener('message', e => handler(e.data));
  }
}

// ---- roteamento de mensagens ----
// Despacha cada mensagem {type, payload} para o handler registrado pela aba dona.
// Os handlers são registrados pelos scripts das abas, carregados depois deste.
class MessageRouter {
  constructor(bridge) {
    this._handlers = {};
    bridge.onMessage(m => this._dispatch(m));
  }

  register(type, fn) { this._handlers[type] = fn; }

  registerAll(map) { Object.assign(this._handlers, map); }

  _dispatch(m) {
    if (!m || !m.type) return;
    const fn = this._handlers[m.type];
    if (fn) fn(m.payload);
  }
}

// ---- troca de abas ----
// Liga os links do <nav>: ativa o link clicado e mostra o .tab correspondente.
class Tabs {
  constructor() {
    document.querySelectorAll('nav a').forEach(a => {
      a.onclick = () => this._activate(a);
    });
  }

  _activate(a) {
    document.querySelectorAll('nav a').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    a.classList.add('active');
    document.getElementById(a.dataset.tab).classList.add('active');
  }
}

// ---- bootstrap ----
SecAgent.bridge = new Bridge();
SecAgent.router = new MessageRouter(SecAgent.bridge);
new Tabs();

// Shim global usado pelos onclick inline do dashboard.html (cmd('scanOnly') etc.).
function cmd(c) { SecAgent.bridge.send(c); }
