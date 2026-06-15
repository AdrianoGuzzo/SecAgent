# SecAgent

Agente de segurança defensiva para Windows que roda 24/7 como serviço,
faz **varredura periódica** do estado de configuração + **monitoramento
em tempo real** de processos/rede/event logs, e usa o **Claude Code CLI**
(consumindo tokens da sua assinatura Pro/Max, não a API paga) para produzir
relatórios acionáveis e disparar análise ad-hoc de incidentes.

Desenhado para uso pessoal por alguém que está aprendendo segurança defensiva:
cada finding explica **por que** algo é risco, não só o que fazer.

---

## Visão geral

```
+----------------------------------------------------------------------+
| SecAgent.Service (Windows Service, LocalSystem, 24/7)                |
|                                                                      |
|  PROACTIVE (scheduled or trigger)   REACTIVE (real-time)             |
|  --------------------------------   -----------------------          |
|  [Scheduler 24h]   [TriggerWatcher] [ProcessMonitor]   WMI           |
|     |                |              [NetworkMonitor]   30s poll      |
|     |                |              [EventLogMonitor]  push          |
|     v                v                       |                       |
|     [ScanRunner] --> SecurityScanner        v                        |
|       |              7 collectors    Channel<SecurityEvent>          |
|       |              (incl. FirewallRulesCollector)                  |
|       |                                      |                       |
|       v                                      v                       |
|   ScanResult.json                    [SuspiciousEventProcessor]      |
|       |                               - JSONL forensics              |
|       v                               - sliding 30min window         |
|  [PromptBuilder]                      - threshold ≥5 events?         |
|   token reduction                            |                       |
|   + firewall rule correlation                v                       |
|       |                              [ClaudeAnalyzer                 |
|       v                                .AnalyzeIncidentAsync]        |
|  [ClaudeAnalyzer.AnalyzeAsync]               |                       |
|       |                                      v                       |
|       v                              incident_*.{json,md}            |
|  report_*.{json,md}                          /                       |
|       \                                    /                         |
|        \                                  /                          |
|         v                                v                           |
|     [StatusFileService] -> status.json (overall severity)            |
|     [ProgressTracker]   -> progress.json (live state during work)    |
+----------------------------------------------------------------------+
                                |
                                v
+----------------------------------------------------------------------+
| SecAgent.Tray (WinForms, user session, autostart on login)           |
|   - polls status.json (10s) -> icon color (green/yellow/red)         |
|   - watches progress.json   -> busy icon + tooltip + transition toast|
|   - watches reports/*.md    -> toast on new scan/incident report     |
|   - context menu: force scan-only / force scan+Claude / open last... |
|   - writes triggers/*.trigger to request scans on demand             |
+----------------------------------------------------------------------+
```

**Cadências padrão:**
- Scan completo + análise Claude: 1×/dia (`Scanner.ScanIntervalHours`)
- Monitores em tempo real: contínuos (push/poll conforme o caso)
- Análise Claude de incidente: ad-hoc quando ≥ 5 eventos suspeitos em 30 min, com cooldown de 60 min entre análises

---

## O que cada coletor analisa

| Coletor | Fonte | O que reporta | Sinal de segurança |
|---|---|---|---|
| `OpenPortsCollector` | `IPGlobalProperties` | Todas as portas TCP/UDP em estado LISTENING, com endereço local | Serviços expostos (RDP/SMB/SSH/DB) — vetor #1 de ataque remoto |
| `InstalledSoftwareCollector` | Registry `HKLM64`, `HKLM32`, `HKCU` em `...\Uninstall` | Nome, versão, publisher de cada app | Software vulnerável (CVEs), ferramentas de risco (acesso remoto, launchers não oficiais) |
| `FolderPermissionsCollector` | `DirectoryInfo.GetAccessControl()` (ACLs NTFS) | ACEs e flags de risco em pastas críticas (System32, Program Files, Users, ProgramData\SecAgent) | Permissões frouxas — Everyone/Authenticated Users com Modify/Write/FullControl |
| `DefenderStatusCollector` | WMI `root\Microsoft\Windows\Defender\MSFT_MpComputerStatus` | Antivirus on/off, real-time on/off, tamper protection, idade da assinatura | Defesa baseline desabilitada/desatualizada |
| `FirewallStatusCollector` | WMI `root\StandardCimv2\MSFT_NetFirewallProfile` | Por perfil (Domain/Private/Public): enabled + DefaultInboundAction/OutboundAction | Firewall off em algum perfil; policy "allow by default" |
| `InstalledUpdatesCollector` | WMI `Win32_QuickFixEngineering` | KBs instalados + datas | Idade do último patch — indicador de atrasos no Windows Update |
| `UserAccountsCollector` | WMI `Win32_UserAccount` + grupo Administrators (SID `S-1-5-32-544`) | Contas locais (disabled?, password required?), membros do grupo Administrators | Contas admin sem senha, número excessivo de admins, contas habilitadas que não deveriam estar |

Cada coletor é isolado: se um falhar (ex: WMI indisponível), o `ScanResult`
registra a falha em `Errors[]` e os outros coletores ainda rodam.

---

## Análise por IA (Claude Code)

Após cada scan, o `ClaudeAnalyzer`:

1. Chama `PromptBuilder.Build(scan)` que produz um **ScanSummary** otimizado
   para reduzir tokens:
   - Agrupa portas por `(Protocol, Port)` (1600+ entradas viram ~50)
   - Filtra software de publishers de sistema (Microsoft, AMD, NVIDIA, Intel,
     Dell, HP, Realtek, Logitech, Synaptics) — vira só um contador
   - Remove o ACE detalhado de pastas sem concerns
2. Invoca `claude -p --output-format json --model haiku
   --permission-mode bypassPermissions --system-prompt "..."
   --disallowedTools "*"` com o prompt via **stdin** (evita limite de ~32K
   chars do command-line do Windows).
3. Parseia o JSON envelope da resposta e extrai a análise estruturada:
   - `risk_level`: low / medium / high / critical
   - `summary`: 2-3 frases do estado geral
   - `findings[]`: severity, category, title, description, recommendation, evidence
4. Persiste em dois formatos:
   - `report_YYYY-MM-DD_HHmmss.json` — estruturado, para diff e tooling futuro
   - `report_YYYY-MM-DD_HHmmss.md` — humano, ordenado por severidade

**Modelo:** Haiku 4.5 por padrão. Sonnet também funciona (mais caro, qualidade
similar nos testes). Trocável em `appsettings.json`.

**Custo:** ~$0.16 equivalente API por scan diário (~$5/mês). Como usa OAuth da
assinatura via `setup-token`, **não sai dinheiro da conta** — consome do
quota da assinatura Pro/Max.

---

## Monitoramento em tempo real (Fase 3)

Três monitores rodam em paralelo ao Worker, alimentando um `Channel<SecurityEvent>`
compartilhado. Um processador de eventos drena o canal, persiste tudo em JSONL
diário (forensics), e dispara análise Claude ad-hoc quando o limiar é cruzado.

| Monitor | Fonte | Quando emite evento |
|---|---|---|
| `ProcessMonitor` | WMI `__InstanceCreationEvent ISA Win32_Process WITHIN 2` | Processo iniciado de path "suspeito" (`\Temp\`, `\Downloads\`, `\AppData\Local\Temp\`, `\Users\Public\`). Demais startups são silenciosamente descartados. |
| `NetworkMonitor` | `IPGlobalProperties.GetActiveTcpConnections()` polled every 30s | Nova conexão TCP ESTABLISHED para IP **público** (não RFC1918/loopback/CGNAT) em porta **fora da whitelist** (80, 443, 53, 123). |
| `EventLogMonitor` | `EventLogWatcher` push-based em `Security` e `System` | Event IDs configurados: 4625 (logon falho), 4720 (conta criada), 4732 (admin group add), 4740 (lockout), 1102 (audit log cleared), 7045 (novo serviço). |

**Filtro de auto-referência:** `Monitors.SelfReferenceFragments: ["SecAgent"]`
no `appsettings.json` faz os monitores ignorarem qualquer evento/processo cujo
path/descrição contenha o fragmento. Necessário para evitar que o agente
flag a própria instalação/restart como atividade suspeita.

**Processador de incidentes:**
- Channel bounded (1000, DropOldest) — produtor não bloqueia se Claude estiver lento
- Persiste cada evento em `C:\ProgramData\SecAgent\events\events_YYYY-MM-DD.jsonl`
- Sliding window de 30 min em memória
- Se `count ≥ 5` AND último incident analysis tem `≥ 60 min` → invoca
  `ClaudeAnalyzer.AnalyzeIncidentAsync(events)`
- Gera `incident_TIMESTAMP.{json,md,events.json}` em `reports/`

**Prompt do incidente é diferente do scan** — pede ao Claude: severity,
title, summary, recommended_actions[]. Custo típico: ~$0.025 por incidente
(eventos são pequenos vs. scan completo).

---

## Tray + notificações (Fase 4)

`SecAgent.Tray` é um app WinForms separado que roda na sessão do usuário (não
no serviço — Windows Services não têm UI por design). Auto-start no login via
HKCU Run key.

**O que faz:**
- Polls `C:\ProgramData\SecAgent\status.json` a cada 10s
- Ícone na bandeja muda de cor conforme `OverallSeverity`:
  - **Verde** (`SystemIcons.Shield`) → tudo low
  - **Amarelo** (`SystemIcons.Warning`) → último report medium/unknown
  - **Vermelho** (`SystemIcons.Error`) → último report high/critical
- Tooltip: resumo do último scan + último incident
- `FileSystemWatcher` em `reports\*.md` → toast notification quando novo
  arquivo aparece (warning para incident, info para scan)
- Menu de contexto (botão direito): abrir último scan/incident, pastas, atualizar, sair
- Duplo-clique no ícone: abre último scan report

**Comunicação Service ↔ Tray:** apenas via arquivo `status.json`. Service
escreve (singleton `StatusFileService`, thread-safe), Tray lê. Zero IPC,
zero ports.

---

## Disparo manual via tray (Fase 4.1)

Os 2 primeiros itens do menu de contexto do tray permitem rodar sob demanda
sem esperar o scan diário ou reiniciar o serviço:

- **Forçar scan agora (sem Claude — grátis)** — coleta dados e salva
  `scan_*.json`. ~5s. Sem custo de tokens. Útil para "snapshot rápido"
  depois de mudar algo no sistema.
- **Forçar scan + análise Claude (~$0.16)** — pipeline completo
  scan→Claude→report. ~60-90s. Útil quando quer feedback agora.

**Mecanismo:** Tray escreve `C:\ProgramData\SecAgent\triggers\<tipo>.trigger`
(usuário tem permissão Write/CreateFiles na pasta — Service ajusta a ACL no
startup). Service vê via `FileSystemWatcher`, dispatch para
`ScanRunner.RunScanOnlyAsync` ou `RunScanAndAnalyzeAsync`, deleta o trigger.

**Debounce:** 30s no Tray (client-side) e 30s no Service (server-side, por
tipo de trigger). Cliques rápidos viram toast "Aguarde Xs entre solicitações".

**Triggers órfãos** (Tray escreveu, Service estava parado) são drenados
quando o Service sobe.

---

## Correlação Windows Firewall ↔ portas abertas (Fase 4.2)

Sem essa correlação, o scanner via "RDP/SMB/PostgreSQL escutando em 0.0.0.0"
e o Claude flagava como CRÍTICO mesmo quando havia regras Block do Windows
Firewall mitigando a exposição. Agora:

1. `FirewallRulesCollector` lê todas as regras inbound habilitadas via
   COM `HNetCfg.FwPolicy2` (mesma API que o `New-NetFirewallRule` usa).
2. `PromptBuilder` pré-correlaciona cada porta com as regras Block que
   afetam ela (matching por Protocol + LocalPorts).
3. Template do prompt orienta Claude: porta com regra Block aplicável =
   **mitigada**, não emite finding crítico de exposição.

**Filtros para manter o prompt < 200K tokens:**
- Apenas regras `Action=Block` viram MatchedRule por porta (Allow rules não
  alteram exposição)
- UDP listeners removidos (só TCP — UDP é dominado por sockets ephemerais
  ruidosos)
- Wildcard-port Allow rules ignoradas no matching
- Max 5 matched rules por porta, `RemoteAddresses` truncado a 120 chars
- Endereços IPv6 colapsados em `[IPv6:other]`

**Custo típico:** ~$0.08-0.12 por análise (Haiku, prompt ~40KB).

**Como o relatório muda:** RDP/SMB/PostgreSQL agora aparecem em finding
`[INFO]` de **elogio** quando as regras Block estão presentes:
> "Serviços críticos bloqueados de internet — Configuração defensiva correta"

---

## Feedback ao vivo durante scan + análise (Fase 4.3)

Antes: clique no menu → toast inicial → 60-90s de silêncio → toast final.
Agora: visibilidade contínua via ícone busy + tooltip dinâmico + transition
toast.

**Mecanismo:** Service escreve `C:\ProgramData\SecAgent\progress.json` em
cada transição (`scanning` → `analyzing` → idle/deleted). Tray observa via
`FileSystemWatcher` e atualiza UI:

- **Ícone vira `SystemIcons.Information` (azul "busy")** enquanto há
  progresso ativo.
- **Tooltip atualiza a cada 2s** com elapsed time: `SecAgent — Claude
  analisando (haiku)... 47s`.
- **Toast extra na transição scan→analyze:** "Scan concluído. Claude
  analisando..." — só dispara nesse momento (não periódico, não invasivo).
- **Ao terminar** (`progress.json` deletado): ícone restaura cor de severity
  baseada em `status.json`, tooltip volta ao normal.

`ProgressTracker` (singleton thread-safe) é injetado no `ScanRunner`. Tanto
o Worker (trigger=scheduled) quanto o TriggerWatcher (trigger=tray) passam
pelo mesmo ponto de instrumentação. Garantia de cleanup via `try/finally`
em torno do `Clear()`.

---

## Pré-requisitos

- Windows 10/11
- .NET 8 SDK (build) ou Runtime (run) — `dotnet --version` ≥ 8.0
- Claude Code CLI v2.1+ instalado e disponível no PATH ou em
  `C:\Users\<usuario>\.local\bin\claude.exe`
- Assinatura Claude Pro ou Max ativa
- Conta admin local no Windows (para instalar o serviço e setar env var de máquina)

---

## Instalação

Há dois caminhos: o **instalador gráfico** (recomendado para máquina limpa) ou
a **instalação manual** via scripts (abaixo, melhor para a máquina de
desenvolvimento que tem o repo + .NET SDK).

### Opção A — Instalador (`SecAgent-Setup.exe`)

O projeto `SecAgent.Installer\` gera um instalador único (Inno Setup) que
empacota Service + Tray **self-contained** (não precisa de .NET na máquina
alvo), registra o serviço, configura o token do Claude e o autostart do Tray.

```powershell
# Na máquina de build (precisa .NET 8 SDK + Inno Setup 6):
#   winget install JRSoftware.InnoSetup
powershell -ExecutionPolicy Bypass -File C:\Projetos\SecAgent\SecAgent.Installer\build-installer.ps1
# -> SecAgent.Installer\output\SecAgent-Setup.exe
```

Rode o `SecAgent-Setup.exe` (pede UAC). No wizard, a página **Claude Code**
detecta o `claude.exe` e deixa você **colar** um token existente, **gerar** um
na hora (`claude setup-token`) ou **pular**. Detalhes e caveats em
`SecAgent.Installer\CLAUDE.md`.

> Mesmo usando o instalador, o token precisa ser gerado via `claude setup-token`
> (auth OAuth interativa no browser) — o instalador apenas o captura/grava em
> Machine scope. Se escolher "pular", configure depois (Opção B, passos 1–2).

### Opção B — Instalação manual (scripts)

#### 1. Autenticar o Claude Code

Em um PowerShell normal (sua sessão de usuário):
```powershell
claude setup-token
```
Isso abre o navegador, você autoriza, e o CLI imprime um token long-lived
(`sk-ant-oat01-...`).

#### 2. Salvar o token como env var

Em **PowerShell Administrador**:
```powershell
powershell -ExecutionPolicy Bypass -File C:\Projetos\SecAgent\SecAgent.Service\update-token.ps1
```
Cole o token quando pedido (não vai ser ecoado — usa `Read-Host -AsSecureString`).
O script salva em escopo **User** e **Machine** (necessário porque o serviço
roda como LocalSystem).

> **Nota:** o `update-token.ps1` está em `SecAgent.Spike\` no histórico inicial.
> Para o serviço, pode usar o mesmo script — o que importa é a env var
> `CLAUDE_CODE_OAUTH_TOKEN` estar setada em scope Machine.

#### 3. Deployar o serviço (publish + install em uma só passada)

Em **PowerShell Administrador** — o script para o serviço (se já existir),
publica o binário, re-registra e inicia:
```powershell
powershell -ExecutionPolicy Bypass -File C:\Projetos\SecAgent\SecAgent.Service\deploy.ps1
```

O script:
- Para `SecAgent` se rodando (libera o EXE para sobrescrever)
- Executa `dotnet publish -c Release -o bin\publish --no-self-contained`
- Re-registra como Windows Service com:
  - `obj= LocalSystem` (privilégios para WMI Defender, ACLs, EventLog Security)
  - `start= auto` (sobe junto com o Windows)
  - failure action: restart automático em até 3 crashes/24h
- Inicia o serviço

A primeira análise roda imediatamente (~1 min de scan + ~1 min de análise Claude).

> Para uma instalação **limpa** (primeira vez, sem o serviço já registrado),
> alternativa: `install-service.ps1` — assume que `bin\publish` já foi gerado.
> O `deploy.ps1` é o caminho universal para qualquer update.

#### 4. Instalar o Tray (sem admin)

Em **PowerShell normal** (sessão do seu usuário):
```powershell
powershell -ExecutionPolicy Bypass -File C:\Projetos\SecAgent\SecAgent.Tray\install-tray.ps1
```

O script:
- Para qualquer instância prévia do `SecAgent.Tray`
- Publica `SecAgent.Tray.exe`
- Registra em `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SecAgentTray`
  (auto-start em cada login)
- Inicia o Tray imediatamente

Procure o ícone do SecAgent na bandeja (próximo ao relógio).

#### 5. Verificar

```powershell
Get-Service SecAgent                                # Status=Running
Get-Process SecAgent.Tray                           # rodando como seu usuário
Get-ChildItem C:\ProgramData\SecAgent\scans        # JSON do scan
Get-ChildItem C:\ProgramData\SecAgent\reports      # report_*.{json,md} e incident_*.{json,md}
Get-Content   C:\ProgramData\SecAgent\status.json  # estado agregado
```

Para ler o último relatório de scan:
```powershell
notepad (Get-ChildItem C:\ProgramData\SecAgent\reports\report_*.md | Sort-Object LastWriteTime -Desc | Select-Object -First 1).FullName
```

Para ler o último incidente:
```powershell
notepad (Get-ChildItem C:\ProgramData\SecAgent\reports\incident_*.md | Sort-Object LastWriteTime -Desc | Select-Object -First 1).FullName
```

---

## Configuração — `appsettings.json`

Editar em `C:\Projetos\SecAgent\SecAgent.Service\bin\publish\appsettings.json`
(no binário publicado; o serviço lê dali). Depois reinicie:
`Restart-Service SecAgent` (como admin).

```json
{
  "Scanner": {
    "OutputDirectory": "C:\\ProgramData\\SecAgent\\scans",
    "ScanIntervalHours": 24,
    "RunOnStartup": true,
    "CriticalFolders": [
      "C:\\Windows\\System32",
      "C:\\Program Files",
      "C:\\ProgramData\\SecAgent",
      "C:\\Users"
    ]
  },
  "Claude": {
    "ExePath": "C:\\Users\\adria\\.local\\bin\\claude.exe",
    "TokenEnvVarName": "CLAUDE_CODE_OAUTH_TOKEN",
    "Model": "haiku",
    "TimeoutSeconds": 300,
    "ReportsDirectory": "C:\\ProgramData\\SecAgent\\reports",
    "AnalyzeAfterScan": true
  }
}
```

| Campo | Default | Notas |
|---|---|---|
| `Scanner.ScanIntervalHours` | 24 | Frequência do scan completo. Para testes use 1. |
| `Scanner.RunOnStartup` | true | Roda um scan logo que o serviço sobe |
| `Scanner.CriticalFolders` | 4 paths | Pastas auditadas pelo `FolderPermissionsCollector` |
| `Claude.Model` | `haiku` | `haiku` ou `sonnet`. Sonnet ~3x mais caro |
| `Claude.AnalyzeAfterScan` | true | `false` para gerar só JSON sem chamar Claude |
| `Claude.TimeoutSeconds` | 300 | Timeout da chamada `claude -p` |
| `Claude.ExePath` | path absoluto | Ajuste se claude não estiver em `~/.local/bin` |
| `Monitors.SelfReferenceFragments` | `["SecAgent"]` | Dropa eventos/processos com path/descrição contendo qualquer fragmento — evita auto-flag |
| `Monitors.ProcessMonitorEnabled` | true | Liga o WMI watcher de novos processos |
| `Monitors.SuspiciousPathFragments` | 4 paths | Paths que disparam evento de processo (`\Temp\`, `\Downloads\`, etc.) |
| `Monitors.NetworkMonitorEnabled` | true | Liga o poll de conexões TCP |
| `Monitors.NetworkPollSeconds` | 30 | Intervalo do poll |
| `Monitors.NetworkPortWhitelist` | [80,443,53,123] | Portas remotas que NÃO disparam evento |
| `Monitors.EventLogMonitorEnabled` | true | Liga subscription nos canais Security/System |
| `Monitors.SecurityEventIds` | 4625, 4720, 4732, 4740, 1102 | Event IDs vigiados no canal Security |
| `Monitors.SystemEventIds` | 7045 | Event IDs vigiados no canal System |
| `Monitors.IncidentEventThreshold` | 5 | Quantos eventos na janela para disparar Claude |
| `Monitors.IncidentWindowMinutes` | 30 | Sliding window |
| `Monitors.IncidentCooldownMinutes` | 60 | Tempo mínimo entre dois incident analyses |
| `Monitors.ChannelCapacity` | 1000 | Tamanho máx do buffer entre monitores e processor (DropOldest) |

---

## Estrutura de pastas

### Código-fonte
```
C:\Projetos\SecAgent\
├── SecAgent.sln
├── README.md                              <- este arquivo
│
├── SecAgent.Service\                      <- serviço (Worker + monitores)
│   ├── Program.cs                         <- DI + AddWindowsService + Channel<SecurityEvent>
│   ├── Worker.cs                          <- BackgroundService, agenda scans diários
│   ├── SecurityScanner.cs                 <- orquestra os 7 coletores
│   ├── ScannerOptions.cs
│   ├── StringExtensions.cs
│   ├── appsettings.json
│   ├── deploy.ps1                         <- stop + publish + reinstall (uso principal)
│   ├── install-service.ps1                <- só reinstala (assume bin\publish existe)
│   ├── uninstall-service.ps1
│   ├── ScanRunner.cs                      <- orquestra scan + Claude; instrumenta ProgressTracker
│   ├── Collectors\                        <- Fase 1 + 4.2
│   │   ├── OpenPortsCollector.cs
│   │   ├── InstalledSoftwareCollector.cs
│   │   ├── FolderPermissionsCollector.cs
│   │   ├── DefenderStatusCollector.cs
│   │   ├── FirewallStatusCollector.cs
│   │   ├── FirewallRulesCollector.cs      <- Fase 4.2: regras inbound via HNetCfg.FwPolicy2 COM
│   │   ├── InstalledUpdatesCollector.cs
│   │   └── UserAccountsCollector.cs
│   ├── Monitors\                          <- Fase 3
│   │   ├── ProcessMonitor.cs              <- WMI Win32_Process
│   │   ├── NetworkMonitor.cs              <- TCP poll + diff
│   │   ├── EventLogMonitor.cs             <- EventLogWatcher Security/System
│   │   ├── SuspiciousEventProcessor.cs    <- consumer do channel
│   │   └── MonitorOptions.cs
│   ├── Triggers\                          <- Fase 4.1
│   │   ├── TriggerWatcher.cs              <- FSWatcher em triggers/*.trigger
│   │   └── TriggerOptions.cs
│   ├── Models\
│   │   ├── ScanResult.cs                  <- Fase 1 + 4.2 (FirewallRule)
│   │   ├── AnalysisResult.cs              <- Fase 2 (scan analysis)
│   │   ├── SecurityEvent.cs               <- Fase 3 (event + incident report)
│   │   ├── AgentStatus.cs                 <- Fase 4 (status.json schema)
│   │   └── AnalysisProgress.cs            <- Fase 4.3 (progress.json schema)
│   ├── Analysis\
│   │   ├── ClaudeAnalyzer.cs              <- AnalyzeAsync + AnalyzeIncidentAsync
│   │   ├── ClaudeOptions.cs
│   │   ├── PromptBuilder.cs               <- token reduction + firewall correlation (4.2)
│   │   ├── StatusFileService.cs           <- Fase 4 - escreve status.json
│   │   └── ProgressTracker.cs             <- Fase 4.3 - escreve/deleta progress.json
│   └── bin\publish\                       <- gerado pelo dotnet publish
│       └── SecAgent.Service.exe
│
├── SecAgent.Tray\                         <- Fase 4: app de bandeja (user-mode)
│   ├── Program.cs
│   ├── TrayApplicationContext.cs          <- NotifyIcon, menu, watchers (status, reports, scans, progress)
│   ├── AgentStatus.cs                     <- mirror do schema do service
│   ├── AnalysisProgress.cs                <- Fase 4.3 mirror
│   ├── install-tray.ps1                   <- registra HKCU\...\Run, sem admin
│   ├── uninstall-tray.ps1
│   └── bin\publish\
│       └── SecAgent.Tray.exe
│
└── SecAgent.Spike\                        <- spike histórico (Fase 0, descartável)
    ├── register-service.ps1
    ├── unregister-service.ps1
    └── update-token.ps1                   <- gerencia env var CLAUDE_CODE_OAUTH_TOKEN
```

### Runtime data (gerado em tempo de execução)
```
C:\ProgramData\SecAgent\
├── scans\
│   └── scan_2026-06-13_153340.json        <- snapshot bruto do sistema (Fase 1)
├── reports\
│   ├── report_2026-06-13_154112.json      <- análise Claude do scan (Fase 2)
│   ├── report_2026-06-13_154112.md        <- mesma análise em markdown
│   ├── incident_2026-06-14_024116.json    <- análise Claude de incidente (Fase 3)
│   ├── incident_2026-06-14_024116.md
│   └── incident_2026-06-14_024116.events.json   <- eventos brutos que dispararam
├── events\
│   └── events_2026-06-14.jsonl            <- forensics diário (Fase 3, append-only)
├── triggers\                              <- Fase 4.1: Tray escreve, Service consome
│   └── (scan-only.trigger | scan-and-analyze.trigger)  <- effêmero, deletado após processar
├── status.json                            <- Fase 4: estado agregado (Tray lê a cada 10s)
└── progress.json                          <- Fase 4.3: estado vivo durante work (existe só durante scan/analyze)
```

Logs do serviço Windows propriamente dito ficam no **Event Viewer** sob
`Windows Logs → Application` (source `SecAgent` ou `.NET Runtime`).

---

## Operações comuns

### Ver o estado atual de tudo
```powershell
Get-Service SecAgent | Format-Table Name, Status, StartType
Get-Process SecAgent.Tray -ErrorAction SilentlyContinue
Get-Content C:\ProgramData\SecAgent\status.json
```

### Forçar um scan agora (sem esperar 24h)
```powershell
Restart-Service SecAgent      # roda RunOnStartup imediatamente após restart
```

### Ver o último relatório de scan / incidente
```powershell
notepad (Get-ChildItem C:\ProgramData\SecAgent\reports\report_*.md   | Sort-Object LastWriteTime -Desc | Select-Object -First 1).FullName
notepad (Get-ChildItem C:\ProgramData\SecAgent\reports\incident_*.md | Sort-Object LastWriteTime -Desc | Select-Object -First 1).FullName
```

### Inspecionar eventos do dia (forensics)
```powershell
$f = "C:\ProgramData\SecAgent\events\events_$(Get-Date -Format yyyy-MM-dd).jsonl"
$events = Get-Content $f | ForEach-Object { $_ | ConvertFrom-Json }
$events | Group-Object Source, Severity | Format-Table Count, Name -AutoSize
$events | Where-Object {$_.Details.eventId -eq '4625'} | ForEach-Object {$_.Details.prop19} | Group-Object | Sort-Object Count -Desc   # IPs atacantes
```

### Atualizar código (rebuild + redeploy)
```powershell
# Service (admin)
powershell -ExecutionPolicy Bypass -File C:\Projetos\SecAgent\SecAgent.Service\deploy.ps1
# Tray (user)
powershell -ExecutionPolicy Bypass -File C:\Projetos\SecAgent\SecAgent.Tray\install-tray.ps1
```

### Trocar o modelo Claude
Editar `bin\publish\appsettings.json` → `Claude.Model` para `sonnet` ou `haiku`,
depois `Restart-Service SecAgent` (admin).

### Atualizar o token Claude (quando expirar)
```powershell
# 1. gerar novo token (interativo, abre browser)
claude setup-token
# 2. salvar em User + Machine scope (admin)
powershell -ExecutionPolicy Bypass -File C:\Projetos\SecAgent\SecAgent.Spike\update-token.ps1
# 3. reiniciar o serviço para pegar a nova env var (admin)
Restart-Service SecAgent
```

### Desinstalar
```powershell
# Tray (user)
powershell -ExecutionPolicy Bypass -File C:\Projetos\SecAgent\SecAgent.Tray\uninstall-tray.ps1
# Service (admin)
powershell -ExecutionPolicy Bypass -File C:\Projetos\SecAgent\SecAgent.Service\uninstall-service.ps1
```
Não remove `C:\ProgramData\SecAgent\` nem a env var (preservados para reinstalar).

---

## Custos e consumo de tokens

| Item | Custo equivalente API | Frequência típica | Mensal estimado |
|---|---|---|---|
| Scan diário com Haiku 4.5 | ~$0.16 | 1×/dia | ~$5 |
| Scan diário com Sonnet | ~$0.47 | 1×/dia | ~$14 |
| Incident analysis (Haiku, evento real) | ~$0.025 | sob demanda, com cooldown 60min | depende do ambiente |

**Importante:** esses valores são **equivalentes API** — o consumo real sai do
quota da sua assinatura Pro/Max, não da sua conta bancária. Mas é proxy útil
para entender quanto da quota você gasta.

Pontos a considerar:
- Scan diário gera ~50KB de prompt mesmo após otimização. Pro tem limites
  por janela de 5h — uma execução isolada não esgota, mas se você multiplicar
  por outras tarefas Claude no dia, fique atento.
- Incidentes são baratos (~$0.025 cada) e disparam só com correlação real
  (≥5 eventos suspeitos em 30 min). O cooldown de 60 min evita escalada.
- Para reduzir mais: habilite `Claude.AnalyzeAfterScan=false` (gera só JSON,
  sem chamar Claude), ou aumente `Scanner.ScanIntervalHours=168` para 1×/semana.

---

## Segurança e privacidade

- **Dados enviados ao Claude:** o ScanSummary contém nomes de processos
  hipotéticos (via portas), software instalado, IPs locais, nomes de contas
  de usuário, hotfixes. **Não inclui** senhas, arquivos pessoais, conteúdo
  de documentos, histórico de navegação.
- **Onde fica:** os scans e relatórios ficam só em `C:\ProgramData\SecAgent\`
  no seu próprio disco. Nada é uploadado além do que vai para a API do Claude.
- **Token de autenticação:** salvo em env var de escopo Machine. Qualquer
  processo da máquina pode lê-lo. Para máquina pessoal isso é aceitável; para
  ambiente compartilhado, considere refatorar para DPAPI-encrypted file.
- **Privilégios:** o serviço roda como `LocalSystem` (privilégios máximos).
  Necessário para ler WMI Defender, ACLs sensíveis, lista completa de processos.

---

## Roadmap

**Fases concluídas:**
- **Fase 1** — Scanner de configuração (7 coletores) ✓
- **Fase 2** — Integração com Claude (análise diária, otimização tokens) ✓
- **Fase 3** — Monitoramento em tempo real (process / network / event log) ✓
- **Fase 4** — Tray icon + toast notifications + status.json ✓
- **Fase 4.1** — Trigger manual via tray (scan-only OU scan+Claude) ✓
- **Fase 4.2** — Coleta de regras inbound do Windows Firewall + correlação no prompt ✓
- **Fase 4.3** — Feedback ao vivo durante scan + análise Claude (tooltip + busy icon + transition toast) ✓

**Próximas fases (não implementadas):**
- **Baseline diff** — só enviar para Claude o que mudou desde o último scan
  (potencial 10x menos tokens em dias estáveis)
- **CVE local sync** — banco NVD atualizado periodicamente; cruzar com
  `InstalledSoftware` antes do prompt
- **VirusTotal integration** — hash de arquivos suspeitos via API free tier
- **Resposta automática** — bloquear IP atacante no firewall após N incidentes
  confirmados pelo Claude
- **Parent process resolution** — resolver PPID → nome no `ProcessMonitor` para
  detectar parent-child anomalies (clássico: `word.exe → powershell.exe`)
- **Dashboard web local** em `localhost:5000` com gráficos históricos

---

## Troubleshooting

### Serviço não inicia
- `Get-EventLog -LogName Application -Source SecAgent -Newest 20` para ver
  exceções
- Confirme que `.NET 8 Runtime` está instalado: `dotnet --list-runtimes`
- Confirme `Test-Path C:\Projetos\SecAgent\SecAgent.Service\bin\publish\SecAgent.Service.exe`

### Análise Claude falha com "Not logged in"
- Token expirou ou foi removido. Re-rode `claude setup-token` +
  `update-token.ps1` e `Restart-Service SecAgent`.

### Análise Claude falha com Win32 error 206 ("filename too long")
- Não deveria acontecer (o prompt vai por stdin). Se acontecer, confirme que
  está rodando a versão atual de `ClaudeAnalyzer.cs` (deve ter
  `RedirectStandardInput = true`).

### Custo por scan inesperadamente alto
- Verifique `Claude.Model` em appsettings.json — se mudou para `sonnet`/`opus`
- Verifique se algum coletor está gerando dados excessivos via inspeção do
  arquivo `scans\*.json`

### Scan não encontra Defender/Firewall (campos null)
- Provavelmente o serviço não tem privilégio para acessar WMI desses
  namespaces. Confirme que está rodando como `LocalSystem`:
  `(Get-WmiObject Win32_Service -Filter "Name='SecAgent'").StartName`
  deve retornar `LocalSystem`.

### Quero ver o que o serviço está fazendo em tempo real
Pare o serviço e rode como console:
```powershell
Stop-Service SecAgent
cd C:\Projetos\SecAgent\SecAgent.Service
$env:CLAUDE_CODE_OAUTH_TOKEN = [Environment]::GetEnvironmentVariable('CLAUDE_CODE_OAUTH_TOKEN','User')
dotnet run
```
Logs vão para o console em tempo real. `Ctrl+C` para parar. Não esqueça de
`Start-Service SecAgent` depois.

### Tray não aparece na bandeja
- Confirme processo rodando: `Get-Process SecAgent.Tray`
- Se ausente, rode manualmente: `& "C:\Projetos\SecAgent\SecAgent.Tray\bin\publish\SecAgent.Tray.exe"`
- Se rodando mas ícone invisível, abra "Ícones da bandeja" do Windows e deixe
  o SecAgent.Tray como "sempre visível"
- Confirme registro de auto-start:
  `Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name SecAgentTray`

### Incidente disparou Claude mas relatório flagrou o próprio SecAgent
- Acontecia antes do filtro `SelfReferenceFragments`. Confirme que
  `appsettings.json` no `bin\publish` tem `"SelfReferenceFragments": ["SecAgent"]`
  na seção `Monitors` e que o serviço foi redeployado (`deploy.ps1`) depois.

### EventLogMonitor não captura nada do canal Security
- Requer `SeSecurityPrivilege`. Confirme que o serviço roda como `LocalSystem`:
  `(Get-WmiObject Win32_Service -Filter "Name='SecAgent'").StartName`
- Se rodar como conta de usuário, adicione o usuário ao grupo "Event Log Readers"
  (`net localgroup "Event Log Readers" SEUNOME /add`).

### Muitos eventos de NetworkMonitor para serviços legítimos
- Adicione as portas remotas ao `Monitors.NetworkPortWhitelist` e
  redeploy. Exemplo: para deixar Steam (porta 27015) silencioso:
  `"NetworkPortWhitelist": [80, 443, 53, 123, 27015]`.

---

## Stack técnica

- **.NET 8** (LTS), target `net8.0-windows`
- **Microsoft.Extensions.Hosting.WindowsServices** — host como Windows Service
- **System.Management** — WMI queries
- **Microsoft.Win32** (built-in) — Registry para software instalado
- **System.Security.AccessControl** (built-in) — ACLs NTFS
- **Claude Code CLI** — análise por IA via subprocesso
