# SecAgent — CLAUDE.md (root)

Solution C# (.NET 8) que roda 24/7 no Windows como agente de segurança
defensiva. Faz scans periódicos de configuração + monitora processos/rede/event
logs em tempo real, e invoca o **Claude Code CLI** (consumindo tokens da
assinatura Pro/Max via OAuth, não API) para análise estruturada.

## Projetos

| Projeto | Tipo | Identidade | Função |
|---|---|---|---|
| `SecAgent.Contracts` | Class library (net8.0) | — | Contrato de IPC compartilhado: modelos JSON, `AgentPaths`, `TriggerNames`, `AiModels`, `SeverityLevels`, `ReportNames`, `AtomicFile`, `JsonDefaults` |
| `SecAgent.Service` | Worker Service (.NET 8) | LocalSystem | Toda a lógica de coleta, monitores, Claude e persistência |
| `SecAgent.Tray` | WinForms (.NET 8) | usuário logado | NotifyIcon + menu + toast notifications + painel WebView2 |
| `SecAgent.Service.Tests` | xUnit | — | Testes do Service + Contracts (gate de cobertura 80%) |
| `SecAgent.Tray.Tests` | xUnit | — | Testes do Tray (gate de cobertura 80%) |
| `SecAgent.Installer` | Inno Setup (`.iss` + `.ps1`) | — | Gera `SecAgent-Setup.exe` (self-contained) que instala Service+Tray, registra o serviço e configura o token do Claude. Ver `SecAgent.Installer\CLAUDE.md`. |

Cada projeto tem seu próprio `CLAUDE.md` com detalhes. Este aqui cobre o que
é transversal.

## Comunicação Service ↔ Tray

**Apenas via arquivos em `C:\ProgramData\SecAgent\`** — sem named pipes, sem
sockets. Service roda como LocalSystem, Tray como usuário; o file-based IPC
evita complexidade de permissões cross-session.

O **contrato** (schemas, nomes de arquivo, caminhos) mora em `SecAgent.Contracts`
e é referenciado pelos dois lados — não duplique modelos nem caminhos
(`AgentPaths`, `ReportNames`, `TriggerNames`). Arquivos que o outro lado relê
(status/progress/network/blocked) são gravados com `AtomicFile.WriteAllText`
(tmp + `File.Move`), que no Windows chega aos watchers como **`Renamed`** — todo
`FileSystemWatcher` desses arquivos precisa assinar `Renamed`.

| Arquivo | Direção | Conteúdo |
|---|---|---|
| `status.json` | Service → Tray | Severity agregado + último scan/incident (Tray polleia 10s) |
| `progress.json` | Service → Tray | Estado vivo durante scan/analyze; existe só durante work (Tray watcher + timer 2s) |
| `network.json` | Service → Tray | Snapshot de conexões TCP ativas (entrada/saída + processo); reescrito a cada ~2s pelo `NetworkSnapshotService`. Lido pelo dashboard do Tray |
| `alerts/alert_*.json` | Service → Tray | Alerta imediato de conexão de ENTRADA de IP público; Tray (sempre ativo) emite toast com país. Portas sensíveis = crítico |
| `triggers/*.trigger` | Tray → Service | `scan-only.trigger` ou `scan-and-analyze.trigger`; effêmero (Service deleta após processar) |
| `reports/*.md`, `scans/*.json`, `events/*.jsonl` | Service escreve | Histórico (Tray watcher emite toast quando aparecem) |

## Deploy

Sempre dois passos:

1. **Service** (precisa admin): `SecAgent.Service\deploy.ps1` — stop service +
   `dotnet publish` + re-register + start.
2. **Tray** (sem admin): `SecAgent.Tray\install-tray.ps1` — publish + registra
   em `HKCU\...\Run` + start.

Não tente publicar com o serviço rodando — o exe fica locked. `deploy.ps1`
para o serviço primeiro.

## Auth Claude

Env var **Machine scope** `CLAUDE_CODE_OAUTH_TOKEN` (formato `sk-ant-oat01-...`).
Service (LocalSystem) lê do registro de máquina.

- Gerar token: `claude setup-token` (interativo, abre browser).
- Salvar: `SecAgent.Service\update-token.ps1` (admin) — usa `Read-Host
  -AsSecureString` (não ecoa).
- Verificar: `[Environment]::GetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN','Machine')`

## Gotchas críticos transversais

1. **NÃO usar `--bare` em chamadas ao claude CLI** — esse flag bloqueia OAuth
   e força `ANTHROPIC_API_KEY` (API paga). Trade-off: hooks/CLAUDE.md do
   claude ficam ativos, mas isso é inofensivo no contexto LocalSystem.
2. **Prompt vai por stdin**, não argumento. Command-line do Windows limita
   ~32K chars; scan summary chega facilmente a 50KB+. Use
   `RedirectStandardInput = true` + `claude -p --input-format text`.
3. **Limite de contexto Claude = 200K tokens**. `PromptBuilder` filtra
   agressivamente (UDP fora, system publishers fora, só regras Block, etc.).
   Se mudar coletores, reavaliar tamanho do prompt.
4. **Deploy invalida triggers** — `deploy.ps1` para o serviço, mas triggers
   em `triggers/` ficam. Service drena órfãos no startup (debounce 30s).
5. **Trace logging** em `C:\ProgramData\SecAgent\trace.log` (via `ITraceLog`,
   usado pelo `ClaudeAnalyzer`) é a melhor janela de debug do pipeline
   scan→Claude. EventLog do Windows só pega Warning+ do framework.
6. **Análise com IA é manual por padrão** — `Claude.AnalyzeAfterScan=false` e
   `Monitors.IncidentAutoAnalysisEnabled=false`. O scan diário roda **grátis**
   (scan-only) e incidentes só são logados (sem chamar o Claude). A IA só roda
   quando o usuário clica "scan + análise" (tray/painel) → `RunScanAndAnalyzeAsync`.
   Para religar a IA automática, ponha essas flags em `true`. Custo por análise
   manual: ~$0.08-0.12 equiv (scan) / ~$0.025 (incidente).

## Testes e cobertura (TDD)

```powershell
dotnet test SecAgent.slnx                              # todos os testes
dotnet test SecAgent.slnx -p:CollectCoverage=true      # + gate: falha se < 80% de linhas por projeto
dotnet tool restore
dotnet reportgenerator "-reports:**/TestResults/coverage.cobertura.xml" "-targetdir:coverage-report"
```

- CI (`.github/workflows/ci.yml`, windows-latest) roda o gate em todo PR.
- **Bug novo = teste `Bug_<descrição>` vermelho primeiro**, depois o fix.
- Dependências de SO ficam atrás de interfaces (`SecAgent.Service\Platform\`,
  `TimeProvider`, `AgentPaths`); a lógica fica em classes puras testáveis
  (`internal` + `InternalsVisibleTo` para os projetos de teste).
- **`[ExcludeFromCodeCoverage]` só em adapters finos de SO/UI sem lógica**
  (WMI, COM, registro, P/Invoke, Process, EventLogWatcher, Forms/NotifyIcon).
  Se o adapter ganhou um `if`, extraia a regra para uma classe testada.
- Testes de arquivo usam diretório temporário (`TempDir`) e `FakeTimeProvider`.

## Build commands

```powershell
# Build (sem deploy) — .slnx exige SDK >= 9.0.200 (projetos seguem net8.0)
dotnet build SecAgent.slnx

# Build apenas um projeto
cd SecAgent.Service ; dotnet build

# Rodar Service em modo console (debug, requer admin para Security log)
Stop-Service SecAgent  # admin
cd SecAgent.Service
$env:CLAUDE_CODE_OAUTH_TOKEN = [Environment]::GetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN','User')
dotnet run

# Rodar Tray em foreground
cd SecAgent.Tray ; dotnet run
```

## Runtime data

`C:\ProgramData\SecAgent\` — criado pelo Service. NUNCA versionar.

## Documentação detalhada

- `README.md` — visão de produto, instalação passo-a-passo, troubleshooting
- `SecAgent.Service\CLAUDE.md` — pipeline interno do service
- `SecAgent.Tray\CLAUDE.md` — UI patterns e watchers
- `C:\Users\adria\.claude\plans\plano-agente-de-seguran-a-calm-coral.md` —
  histórico de fases com aprendizados detalhados
