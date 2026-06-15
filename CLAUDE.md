# SecAgent — CLAUDE.md (root)

Solution C# (.NET 8) que roda 24/7 no Windows como agente de segurança
defensiva. Faz scans periódicos de configuração + monitora processos/rede/event
logs em tempo real, e invoca o **Claude Code CLI** (consumindo tokens da
assinatura Pro/Max via OAuth, não API) para análise estruturada.

## Projetos

| Projeto | Tipo | Identidade | Função |
|---|---|---|---|
| `SecAgent.Service` | Worker Service (.NET 8) | LocalSystem | Toda a lógica de coleta, monitores, Claude e persistência |
| `SecAgent.Tray` | WinForms (.NET 8) | usuário logado | NotifyIcon + menu + toast notifications |
| `SecAgent.Spike` | Worker Service (descartável) | LocalSystem | Histórico — validou auth do Claude. **Não deployar.** |

Cada projeto tem seu próprio `CLAUDE.md` com detalhes. Este aqui cobre o que
é transversal.

## Comunicação Service ↔ Tray

**Apenas via arquivos em `C:\ProgramData\SecAgent\`** — sem named pipes, sem
sockets. Service roda como LocalSystem, Tray como usuário; o file-based IPC
evita complexidade de permissões cross-session.

| Arquivo | Direção | Conteúdo |
|---|---|---|
| `status.json` | Service → Tray | Severity agregado + último scan/incident (Tray polleia 10s) |
| `progress.json` | Service → Tray | Estado vivo durante scan/analyze; existe só durante work (Tray watcher + timer 2s) |
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
- Salvar: `SecAgent.Spike\update-token.ps1` (admin) — usa `Read-Host
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
5. **Trace logging** em `C:\ProgramData\SecAgent\trace.log` (escrito por
   `ScanRunner` e `ClaudeAnalyzer`) é a melhor janela de debug do pipeline
   scan→Claude. EventLog do Windows só pega Warning+ do framework.
6. **Token gasto pelo serviço** — daily scan ~$0.10 equiv API; incident
   analysis ~$0.025; triggers via tray = ditto. Monitore consumo se rodar
   triggers manuais com frequência.

## Build commands

```powershell
# Build (sem deploy)
dotnet build C:\Projetos\SecAgent\SecAgent.sln

# Build apenas um projeto
cd C:\Projetos\SecAgent\SecAgent.Service ; dotnet build

# Rodar Service em modo console (debug, requer admin para Security log)
Stop-Service SecAgent  # admin
cd C:\Projetos\SecAgent\SecAgent.Service
$env:CLAUDE_CODE_OAUTH_TOKEN = [Environment]::GetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN','User')
dotnet run

# Rodar Tray em foreground
cd C:\Projetos\SecAgent\SecAgent.Tray ; dotnet run
```

## Runtime data

`C:\ProgramData\SecAgent\` — criado pelo Service. NUNCA versionar.

## Documentação detalhada

- `README.md` — visão de produto, instalação passo-a-passo, troubleshooting
- `SecAgent.Service\CLAUDE.md` — pipeline interno do service
- `SecAgent.Tray\CLAUDE.md` — UI patterns e watchers
- `C:\Users\adria\.claude\plans\plano-agente-de-seguran-a-calm-coral.md` —
  histórico de fases com aprendizados detalhados
