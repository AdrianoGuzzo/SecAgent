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
Program.cs                  # fino: Host + AddWindowsService + AddSecAgentService (excluído da cobertura)
ServiceRegistration.cs      # AddSecAgentService: DI, options validadas (ValidateOnStart), adapters, Channel
Worker.cs                   # BackgroundService — schedule diário via TimeProvider; try/log por execução
ScanRunner.cs               # IScanRunner: orquestra scan+Claude; single-flight (SemaphoreSlim); ProgressTracker
SecurityScanner.cs          # roda os 8 coletores em sequência; Safe() wraps cada um
Diagnostics/TraceLog        # ITraceLog → C:\ProgramData\SecAgent\trace.log (substitui o Trace() estático)

Platform/                   # interfaces dos adapters de SO — ÚNICOS [ExcludeFromCodeCoverage]
  IWmiQuery, IFirewallPolicy (COM FwPolicy2), IUninstallRegistry, IAclReader,
  ITcpConnectionSource (IpHlpApi), INetworkInfo, IEventLogSource, IProcessStartSource,
  IClaudeCli (Process + stdin/stdout + kill da árvore), ISystemEnvironment, ITriggerDirectorySetup
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
  IpClassifier              # público/privado/especial (multicast, 0/8, CGNAT, ::ffff:10.x…) — usado pelos dois monitores
  NetworkMonitor            # poll 30s + diff de conexões TCP estabelecidas (só saída)
  NetworkSnapshotService    # poll 2s; GetExtendedTcpTable (PID por conexão) → network.json;
                            # classifica entrada/saída; SecurityEvent + alerts/alert_*.json p/
                            # entrada de IP público (porta sensível=critical; cooldown por IP)
  Native/IpHlpApi           # P/Invoke GetExtendedTcpTable (v4+v6) com PID; byte-swap de portas
  EventLogMonitor           # EventLogWatcher push em Security + System; regras em EventLogRules
  SuspiciousEventProcessor  # consumer do Channel; journal JSONL sempre grava; IncidentWindow
                            # (sliding window + threshold + cooldown) → análise em background single-flight
  MonitorOptions            # whitelists, eventIds, thresholds, SelfReferenceFragments, SelfServiceNames

Remediation/
  IpBlocker                 # IIpBlocker: regras SecAgent-Block-<ip> In+Out (rollback se uma falhar);
                            # IpAddressPolicy recusa loopback/unspecified/multicast; blocked.json atômico

Triggers/                   # Fase 4.1 — disparo manual via Tray
  TriggerWatcher            # FSWatcher em triggers\*.trigger (watcher antes do drain; guard in-flight)
  TriggerPayloadParser      # IP do block/unblock e {model,effort} do scan-and-analyze
  TriggerOptions            # debounce, enabled

Analysis/                   # Fase 2+
  ClaudeAnalyzer            # IClaudeAnalyzer: AnalyzeAsync (scan) + AnalyzeIncidentAsync; via IClaudeCli
  ClaudeArgsBuilder         # argumentos do claude -p (nunca --bare)
  ClaudeResponseParser      # envelope JSON, code fence, exit code ≠ 0/envelope nulo = falha
  ReportMarkdownRenderer    # .md dos relatórios
  PromptBuilder             # ScanSummary com filtros agressivos; matching firewall ↔ porta; BuildIncident
  ClaudeOptions             # ExePath, Token env var, Model, Timeout, ReportsDir, AnalyzeAfterScan
  StatusFileService         # escreve C:\ProgramData\SecAgent\status.json
  ProgressTracker           # escreve/deleta C:\ProgramData\SecAgent\progress.json

Models/
  ScanResult                # output dos 8 coletores (só o Service usa)
```

Os modelos de IPC (`AnalysisResult`, `SecurityEvent`, `IncidentReport`,
`AgentStatus`, `AnalysisProgress`, `NetworkSnapshot`, `NetworkAlert`,
`BlockedList`) e os caminhos (`AgentPaths`) moram em **`SecAgent.Contracts`**.

## Testes

`SecAgent.Service.Tests` (xUnit + NSubstitute + `FakeTimeProvider`), gate de
80% de linhas em `[SecAgent.Service]*` + `[SecAgent.Contracts]*`.

- Coletores/monitores recebem o adapter de `Platform\` → teste com fake/substitute.
- Lógica dos `BackgroundService` exposta como `internal` (`Poll`, `RunCycle`,
  `ProcessTriggerAsync`…) para o teste dirigir um ciclo por vez.
- Tempo sempre via `TimeProvider` (`Task.Delay(ts, time, ct)`); nada de
  `DateTime.UtcNow` direto.
- Bug corrigido = teste `Bug_<descrição>` no arquivo do componente.

## Padrões de código

- **DI**: todo serviço é registrado em `ServiceRegistration.AddSecAgentService`
  (singleton, pela interface quando existe). Novos coletores/monitores também.
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
   - IPv6 colapsado em `[IPv6:other]` (exceto `::` e `::1`, que ficam visíveis)
   - Max 5 matched rules por porta
4. **LocalSystem necessário** para:
   - WMI `root\Microsoft\Windows\Defender` (Defender status)
   - EventLog Security channel (precisa SeSecurityPrivilege)
   - ACLs sensíveis
5. **HNetCfg.FwPolicy2 COM** acessado via dynamic em `FirewallRulesCollector`.
   Não precisa de NuGet — é built-in Windows. Algumas propriedades de regras
   legacy lançam exceção; cada rule está em try/catch.
6. **Auto-referência é estrita** (evita auto-detecção sem abrir evasão):
   - EventLog: só o 7045 cujo `ServiceName` é **exatamente** um de
     `SelfServiceNames` (default `SecAgent`). Antes, qualquer evento contendo
     "SecAgent" era suprimido — um malware chamado `SecAgentUpdater` passava.
   - Processo: `SelfReferenceFragments` casam só o **nome do arquivo**, ou o
     executável está sob o diretório de instalação do serviço.
7. **Listas de `MonitorOptions` são nullable**; defaults entram via
   `PostConfigure(ApplyDefaults)` só quando a config não define a lista. (O
   binder **anexa** a listas já inicializadas — por isso não use inicializador.)
   Definir a lista no `appsettings.json` **substitui** o default inteiro (ex.:
   `"NetworkPortWhitelist": [8443]` → só 8443). Atenção: `[]` vazio não gera
   chave no JSON e cai no default.
8. **TriggerWatcher cria pasta `triggers/` com ACL** que dá
   `WriteData + CreateFiles` para `Authenticated Users` — Tray (user-mode)
   precisa escrever. Não dá Delete (Service cuida da limpeza).
9. **Debounce dual** em triggers: client-side (Tray) e server-side
   (TriggerWatcher dictionary). Cliques < 30s viram "Aguarde...".
10. **EventLog min level**: o EventLog provider do .NET só loga Warning+.
   `LogInformation` NÃO aparece no Event Viewer. Para debug profundo, injete
   `ITraceLog` (usado pelo ClaudeAnalyzer) → escreve a
   `C:\ProgramData\SecAgent\trace.log`.
11. **Token rotation**: long-lived OAuth pode expirar/ser revogado. Logar
    "Not logged in" no stdout do claude.exe é o sintoma — rodar
    `claude setup-token` + `update-token.ps1` + `Restart-Service SecAgent`.

## Adicionar novo coletor

1. Escrever o teste primeiro (`Collectors/CollectorTests.cs`) com o adapter fake.
2. Criar `Collectors/MyCollector.cs` com método `Collect()` retornando seu
   sub-modelo; acesso ao SO só pelo adapter de `Platform\` (crie um se preciso,
   fino e `[ExcludeFromCodeCoverage]`).
3. Adicionar record em `Models/ScanResult.cs` e campo em `ScanResult`.
4. Inject em `SecurityScanner` constructor.
5. Chamar em `RunFullScan()` com `Safe(...)` wrapper.
6. Registrar em `ServiceRegistration.AddSecAgentService`.
7. Se for relevante para Claude, ajustar `PromptBuilder.Summarize()` para
   incluir no `ScanSummary` (decidir se precisa filtragem/redução de
   tokens).

## Adicionar novo monitor (Fase 3-style)

1. Criar `Monitors/MyMonitor.cs` herdando `BackgroundService`.
2. Inject `Channel<SecurityEvent>` writer + `MonitorOptions` + logger.
3. Emit eventos via `_writer.TryWrite(new SecurityEvent(...))`.
4. Aplicar `_opts.SelfReferenceFragments` se relevante.
5. Registrar em `ServiceRegistration.AddSecAgentService`: `AddHostedService<MyMonitor>()`.
6. Atualizar `MonitorOptions` com config próprios — listas **nullable** com
   default em `ApplyDefaults()`; intervalos validados em `ServiceRegistration`.
7. Extraia o ciclo para um método `internal` testável.

## Adicionar novo trigger type

1. Adicionar a constante em `SecAgent.Contracts/TriggerNames.cs` (compartilhada).
2. Adicionar case no switch de `TriggerWatcher.ProcessTriggerAsync` (+ teste).
3. Adicionar método ao `ScanRunner` (ou outro serviço) que faz o trabalho.
4. No Tray: item em `TrayApplicationContext.BuildMenu` e/ou comando em
   `DashboardCommandParser`, chamando `RequestTrigger(TriggerNames.MyTrigger, "...")`.

## Custo / latência típicos

| Operação | Latência | Custo equivalente API |
|---|---|---|
| Scan completo (8 coletores) | ~1-2s | $0 |
| Análise Claude do scan (Haiku) | ~45-90s | ~$0.08-0.12 |
| Análise Claude de incidente (Haiku) | ~15-30s | ~$0.025 |

Daily scan + análise: ~$3-4/mês equivalente. Sustentável no Pro/Max.

**Por padrão a IA é manual** (`AnalyzeAfterScan=false`,
`IncidentAutoAnalysisEnabled=false`): o scan diário e o de startup rodam
scan-only (grátis) e incidentes só são logados. Só o botão "scan + análise"
(tray/painel) gasta tokens — `RunScanAndAnalyzeAsync` sempre analisa,
independente do `AnalyzeAfterScan` (que controla só o scheduled).
