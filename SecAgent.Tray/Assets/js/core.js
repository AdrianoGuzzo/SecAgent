// ---- core: estado compartilhado, helpers, troca de abas e roteamento ----

// ---- tab switching ----
document.querySelectorAll('nav a').forEach(a => {
  a.onclick = () => {
    document.querySelectorAll('nav a').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    a.classList.add('active');
    document.getElementById(a.dataset.tab).classList.add('active');
  };
});

function cmd(c) {
  try { window.chrome.webview.postMessage({ cmd: c }); } catch (e) {}
}

// ---- state ----
let geoMap = {};        // ip -> {country, countryCode, city, isp}
let lastNetwork = null;
let events = [];
const MAX_FEED = 200;

const SEV = {
  critical: { label: 'CRÍTICO', cls: 'critical', color: '#b91c1c' },
  high:     { label: 'ALTO',    cls: 'high',     color: '#ef4444' },
  medium:   { label: 'MÉDIO',   cls: 'medium',   color: '#f59e0b' },
  low:      { label: 'BAIXO',   cls: 'low',      color: '#ca8a04' },
  info:     { label: 'INFO',    cls: 'info',     color: '#64748b' }
};
function sev(s) { return SEV[(s || 'info').toLowerCase()] || SEV.info; }

function esc(s) {
  return (s == null ? '' : String(s))
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function flag(cc) {
  if (!cc || cc.length !== 2) return '🌐';
  const A = 0x1F1E6;
  return String.fromCodePoint(A + cc.charCodeAt(0) - 65, A + cc.charCodeAt(1) - 65);
}
function timeStr(iso) {
  try { return new Date(iso).toLocaleTimeString('pt-BR', {hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
  catch (e) { return ''; }
}

// ---- message routing ----
// Os handlers on* são definidos nos scripts de cada aba (resumo/conexoes/eventos),
// carregados depois deste. Como são function declarations em escopo global, já
// estão disponíveis quando uma mensagem chega.
window.chrome.webview.addEventListener('message', e => {
  const m = e.data;
  if (!m || !m.type) return;
  switch (m.type) {
    case 'status':   onStatus(m.payload); break;
    case 'progress': onProgress(m.payload); break;
    case 'report':   onReport(m.payload); break;
    case 'incident': onIncident(m.payload); break;
    case 'events':   onEvents(m.payload); break;
    case 'network':  onNetwork(m.payload); break;
    case 'geo':      onGeo(m.payload); break;
  }
});
