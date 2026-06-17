// ---- aba Atividade ao vivo: feed de eventos de segurança ----

class EventosPanel {
  static MAX_FEED = 200;
  static SRC = { process: 'Processo', network: 'Rede', eventlog: 'Windows' };

  constructor() {
    this._events = [];
  }

  register(router) {
    router.register('events', list => this.onEvents(list));
  }

  onEvents(list) {
    if (!Array.isArray(list) || !list.length) return;
    this._events = list.concat(this._events).slice(0, EventosPanel.MAX_FEED);
    this._renderFeed();
  }

  _renderFeed() {
    document.getElementById('evtBadge').textContent = this._events.length;
    const host = document.getElementById('feed');
    if (!this._events.length) {
      host.innerHTML = '<div class="empty">Nenhum evento recente.</div>';
      return;
    }
    host.innerHTML = this._events.map(e => {
      const sv = Severity.of(e.severity);
      return `<div class="feed-item">
        <div class="when">${Format.time(e.timestampUtc)}</div>
        <div class="sdot" style="background:${sv.color}"></div>
        <div class="body">
          <div class="t">${Format.esc(e.title)}</div>
          <div class="d">${Format.esc(e.description)}</div>
          <div class="src">${EventosPanel.SRC[(e.source || '').toLowerCase()] || Format.esc(e.source)}</div>
        </div>
      </div>`;
    }).join('');
  }
}

new EventosPanel().register(SecAgent.router);
