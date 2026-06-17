// ---- controles da análise com IA: escolha de modelo + esforço + botão ----
// Dono do botão "Analisar agora" e dos dropdowns. Também assina 'tokenStatus'
// (mostra/oculta o bloco conforme o token do Claude) e 'aiPrefs' (pré-seleciona
// a última escolha salva, enviada pelo host).

class AnalyzePanel {
  // Modelos oferecidos. 'effort:false' => não suporta --effort (Haiku).
  static MODELS = [
    { value: 'opus',   label: 'Opus 4.8 (mais profundo)', effort: true },
    { value: 'sonnet', label: 'Sonnet 4.6 (equilibrado)', effort: true },
    { value: 'haiku',  label: 'Haiku 4.5 (rápido/barato)', effort: false }
  ];

  // Níveis de esforço (vocabulário do CLI) com rótulos pt-BR.
  static EFFORTS = [
    { value: 'low',    label: 'Baixo' },
    { value: 'medium', label: 'Médio' },
    { value: 'high',   label: 'Alto' },
    { value: 'xhigh',  label: 'Muito alto' },
    { value: 'max',    label: 'Máximo' }
  ];

  // Estimativa grosseira de custo/tempo por modelo, para orientar a escolha.
  // (equivalente de API; a assinatura Pro/Max cobre o uso real.)
  static ESTIMATE = {
    haiku:  '~$0.03 · ~1 min',
    sonnet: '~$0.16 · ~1-2 min',
    opus:   '~$0.60 · ~2-3 min'
  };

  static DEFAULT_MODEL = 'sonnet';
  static DEFAULT_EFFORT = 'high';

  constructor() {
    this._model = document.getElementById('aiModel');
    this._effort = document.getElementById('aiEffort');
    this._effortField = document.getElementById('aiEffortField');
    this._estimate = document.getElementById('aiEstimate');
    this._controls = document.getElementById('aiControls');
    this._btn = document.getElementById('btnAnalyze');
    this._configBtn = document.getElementById('btnConfigAI');

    this._fillSelect(this._model, AnalyzePanel.MODELS, AnalyzePanel.DEFAULT_MODEL);
    this._fillSelect(this._effort, AnalyzePanel.EFFORTS, AnalyzePanel.DEFAULT_EFFORT);

    this._model.addEventListener('change', () => this._sync());
    this._effort.addEventListener('change', () => this._sync());
    this._btn.addEventListener('click', () => this._run());
    this._sync();
  }

  register(router) {
    router.registerAll({
      tokenStatus: p => this.onTokenStatus(p),
      aiPrefs:     p => this.onAiPrefs(p)
    });
  }

  // Token configurado → mostra os controles; senão, mostra "Configurar IA".
  onTokenStatus(p) {
    const configured = !!(p && p.configured);
    if (this._controls) this._controls.style.display = configured ? '' : 'none';
    if (this._btn) this._btn.disabled = !configured;
    if (this._configBtn) this._configBtn.style.display = configured ? 'none' : '';
  }

  // Pré-seleciona a última escolha salva (vinda do host via DataPump).
  onAiPrefs(p) {
    if (!p) return;
    if (p.model) this._model.value = p.model;
    if (p.effort) this._effort.value = p.effort;
    this._sync();
  }

  // Reflete o suporte a esforço do modelo atual e atualiza a estimativa.
  _sync() {
    const model = AnalyzePanel.MODELS.find(m => m.value === this._model.value);
    const supportsEffort = !!(model && model.effort);
    this._effort.disabled = !supportsEffort;
    this._effortField.classList.toggle('disabled', !supportsEffort);
    this._effortField.title = supportsEffort ? '' : 'Haiku não usa nível de esforço';
    this._estimate.textContent = AnalyzePanel.ESTIMATE[this._model.value] || '';
  }

  // Envia o comando composto "scanAndAnalyze:<model>:<effort>" ao host.
  // (mesma convenção de "blockIp:<ip>"). O Service ignora o esforço no Haiku.
  _run() {
    if (this._btn.disabled) return;
    SecAgent.bridge.send(`scanAndAnalyze:${this._model.value}:${this._effort.value}`);
  }

  _fillSelect(sel, options, fallback) {
    sel.innerHTML = options
      .map(o => `<option value="${o.value}">${Format.esc(o.label)}</option>`)
      .join('');
    sel.value = fallback;
  }
}

new AnalyzePanel().register(SecAgent.router);
