# SecAgent.Service — CLAUDE.md

Windows Service (.NET 8) rodando como **LocalSystem**. Responsável por toda
a lógica do agente: coleta, monitores, integração Claude, persistência. O
Tray é só superfície de UI.

> Veja `..\CLAUDE.md` para visão geral da solution e auth do Claude.

## Build e run

```powershell
dotnet build              # do diretório do projeto
dotnet run                # modo console (precisa env var CLAUDE_CODE_OAUTH_TOKEN + service parado)
deploy.ps1                # admin: stop + publish + re-register + start
```

Target: `net8.0-windows`. Não funciona em Linux/macOS (usa System.Management,
HNetCfg.FwPolicy2 COM, EventLogWatcher, NTFS ACLs).

## Organização

```
Program.cs                  # bootstrap DI + AddWindowsService + Channel<SecurityEvent> singleton
Worker.cs                   # BackgroundService — schedule diário; chama ScanRunner com trigger="scheduled"
ScanRunner.cs               # orquestra scan+Claude; instrumenta ProgressTracker
SecurityScanner.cs          # roda os 7 coletores em sequência; Safe() wraps cada um
ScannerOptions.cs           # config do scanner (OutputDirectory, intervalo, pastas críticas)
StringExtensions.cs         # Truncate() helper

Collectors/                 # Fase 1+4.2 — coleta dados do sistema
  OpenPortsCollector        # IPGlobalProperties.GetActiveTcpListeners/UdpListeners
  InstalledSoftwareCollector# Registry HKLM64+HKLM32+HKCU \...\Uninstall
  FolderPermissionsCollector# DirectoryInfo.GetAccessControl() + flag risky ACEs
  DefenderStatusCollector   # WMI root\Microsoft\Windows\Defender MSFT_MpComputerStatus
  FirewallStatusCollector   # WMI root\StandardCimv2 MSFT_NetFirewallProfile (defaults por perfil)
  FirewallRulesCollector    # COM HNetCfg.FwPolicy2 (inbound rules enabled)
  InstalledUpdatesCollector # WMI Win32_QuickFixEngineering
  UserAccountsCollector     # WMI Win32_UserAccount + Win32_Group (admins via SID S-1-5-32-544)

Monitors/                   # Fase 3 — push/poll em tempo real
  ProcessMonitor            # WMI __InstanceCreationEvent ISA Win32_Process WITHIN 2
  NetworkMonitor            # poll 30s + diff de conexões TCP estabelecidas (só saída)
  NetworkSnapshotService    # poll 2s; GetExtendedTcpTable (PID por conexão) → network.json;
                            # classifica entrada/saída; SecurityEvent + alerts/alert_*.json p/
                            # entrada de IP público (porta sensível=critical; cooldown por IP)
  Native/IpHlpApi           # P/Invoke GetExtendedTcpTable (v4+v6) com PID; byte-swap de portas
  EventLogMonitor           # EventLogWatcher push em Security + System
  SuspiciousEventProcessor  # consumer do Channel; sliding window; threshold → Claude
  MonitorOptions            # whitelists, eventIds, thresholds, SelfReferenceFragments

Triggers/                   # Fase 4.1 — disparo manual via Tray
  TriggerWatcher            # FSWatcher em C:\ProgramData\SecAgent\triggers\*.trigger
  TriggerOptions            # debounce, enabled

Analysis/                   # Fase 2+
  ClaudeAnalyzer            # AnalyzeAsync (scan) + AnalyzeIncidentAsync; invoca claude -p
  PromptBuilder             # ScanSummary com filtros agressivos; matching firewall ↔ porta
  ClaudeOptions             # ExePath, Token env var, Model, Timeout, ReportsDir, AnalyzeAfterScan
  StatusFileService         # escreve C:\ProgramData\SecAgent\status.json
  ProgressTracker           # escreve/deleta C:\ProgramData\SecAgent\progress.json

Models/
  ScanResult                # output dos 7 coletores
  AnalysisResult            # output do Claude (Findings + AnalysisMeta com tokens)
  SecurityEvent             # input dos monitores; IncidentReport para análise
  AgentStatus               # schema do status.json
  AnalysisProgress          # schema do progress.json
```

## Padrões de código

- **DI**: todo serviço é `AddSingleton<T>` em `Program.cs`. Novos coletores/
  monitores também.
- **`BackgroundService`** para qualquer loop contínuo. Cancelable via `stoppingToken`.
- **`IOptions<T>`** para config. Lê de `appsettings.json` seção
  correspondente.
- **`Channel<T>`** (System.Threading.Channels) para producer/consumer entre
  monitores e SuspiciousEventProcessor. Bounded com DropOldest.
- **Try/catch + `Safe()` wrapper** em coletores: uma falha não derruba o
  scan inteiro; o erro vira `CollectorError` na ScanResult.
- **FileSystemWatcher** para arquivo-based IPC (Triggers).

## Gotchas críticos

1. **Claude CLI flags**: `claude -p --output-format json --input-format text
   --model haiku --permission-mode bypassPermissions --system-prompt "..."
   --disallowedTools "*"`. **Nunca `--bare`** (mata OAuth).
2. **Prompt via stdin**: `process.StandardInput.WriteAsync(prompt)` —
   command-line limita ~32K chars.
3. **PromptBuilder filtros** (essenciais para ficar < 200K tokens):
   - Drop UDP listeners (são noise — ephemerais)
   - Drop software de system publishers (Microsoft/AMD/NVIDIA/Intel/Dell/etc.)
   - Drop folder ACEs quando sem concerns
   - Drop wildcard Allow firewall rules
   - Só Block rules viram MatchedRule por porta
   - Truncar RemoteAddresses a 120 chars
   - IPv6 colapsado em `[IPv6:other]`
   - Max 5 matched rules por porta
4. **LocalSystem necessário** para:
   - WMI `root\Microsoft\Windows\Defender` (Defender status)
   - EventLog Security channel (precisa SeSecurityPrivilege)
   - ACLs sensíveis
5. **HNetCfg.FwPolicy2 COM** acessado via dynamic em `FirewallRulesCollector`.
   Não precisa de NuGet — é built-in Windows. Algumas propriedades de regras
   legacy lançam exceção; cada rule está em try/catch.
6. **SelfReferenceFragments=["SecAgent"]** — filtro vital para evitar
   auto-detecção (próprio install do serviço gerando event 7045 → Claude
   flagrava como malware). Aplicado em ProcessMonitor e EventLogMonitor.
7. **TriggerWatcher cria pasta `triggers/` com ACL** que dá
   `WriteData + CreateFiles` para `Authenticated Users` — Tray (user-mode)
   precisa escrever. Não dá Delete (Service cuida da limpeza).
8. **Debounce dual** em triggers: client-side (Tray) e server-side
   (TriggerWatcher dictionary). Cliques < 30s viram "Aguarde...".
9. **EndLogger min level**: o EventLog provider do .NET só loga Warning+.
   `LogInformation` NÃO aparece no Event Viewer. Para debug profundo, use
   `Trace()` em ScanRunner.cs / ClaudeAnalyzer.cs → escreve a
   `C:\ProgramData\SecAgent\trace.log`.
10. **Token rotation**: long-lived OAuth pode expirar/ser revogado. Logar
    "Not logged in" no stdout do claude.exe é o sintoma — rodar
    `claude setup-token` + `update-token.ps1` + `Restart-Service SecAgent`.

## Adicionar novo coletor

1. Criar `Collectors/MyCollector.cs` com método `Collect()` retornando seu
   sub-modelo.
2. Adicionar record em `Models/ScanResult.cs` e campo em `ScanResult`.
3. Inject em `SecurityScanner` constructor.
4. Chamar em `RunFullScan()` com `Safe(...)` wrapper.
5. Registrar em `Program.cs`: `builder.Services.AddSingleton<MyCollector>()`.
6. Se for relevante para Claude, ajustar `PromptBuilder.Summarize()` para
   incluir no `ScanSummary` (decidir se precisa filtragem/redução de
   tokens).

## Adicionar novo monitor (Fase 3-style)

1. Criar `Monitors/MyMonitor.cs` herdando `BackgroundService`.
2. Inject `Channel<SecurityEvent>` writer + `MonitorOptions` + logger.
3. Emit eventos via `_writer.TryWrite(new SecurityEvent(...))`.
4. Aplicar `_opts.SelfReferenceFragments` se relevante.
5. Registrar em `Program.cs`: `AddHostedService<MyMonitor>()`.
6. Atualizar `MonitorOptions` com config próprios (whitelists, intervalos).

## Adicionar novo trigger type

1. Adicionar constante `MyTrigger = "my-trigger.trigger"` em `TriggerWatcher`.
2. Adicionar case no switch de `ProcessTriggerAsync`.
3. Adicionar método ao `ScanRunner` (ou outro serviço) que faz o trabalho.
4. Atualizar `TrayApplicationContext.BuildMenu` com novo menu item que
   chama `RequestTrigger(MyTrigger, "...")`.

## Custo / latência típicos

| Operação | Latência | Custo equivalente API |
|---|---|---|
| Scan completo (7 coletores) | ~1-2s | $0 |
| Análise Claude do scan (Haiku) | ~45-90s | ~$0.08-0.12 |
| Análise Claude de incidente (Haiku) | ~15-30s | ~$0.025 |

Daily scan + análise: ~$3-4/mês equivalente. Sustentável no Pro/Max.

**Por padrão a IA é manual** (`AnalyzeAfterScan=false`,
`IncidentAutoAnalysisEnabled=false`): o scan diário e o de startup rodam
scan-only (grátis) e incidentes só são logados. Só o botão "scan + análise"
(tray/painel) gasta tokens — `RunScanAndAnalyzeAsync` sempre analisa,
independente do `AnalyzeAfterScan` (que controla só o scheduled).
