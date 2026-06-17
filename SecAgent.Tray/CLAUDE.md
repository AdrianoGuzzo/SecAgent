# SecAgent.Tray — CLAUDE.md

WinForms (.NET 8) com NotifyIcon na bandeja. Roda **na sessão do usuário**
(não pode rodar dentro do Windows Service por causa do Session 0 isolation).
Auto-start no login via `HKLM\...\Run` (registrado pelo instalador → vale para
todos os usuários). Cada usuário pode remover só a sua cópia (sem admin) pelo
menu "Remover SecAgent deste usuário", que grava o opt-out
`HKCU\Software\SecAgent\TrayDisabled` honrado no `Program.Main` (ver
`UserInstall.cs`). O script dev `install-tray.ps1` continua usando `HKCU\...\Run`
(per-user, sem admin) — só para desenvolvimento.

> Veja `..\CLAUDE.md` para visão geral da solution.

## Build e run

```powershell
dotnet build                 # do diretório do projeto
dotnet run                   # roda em foreground (útil para debug visual)
install-tray.ps1             # SEM admin: publish + HKCU autostart + launch
uninstall-tray.ps1           # remove autostart e mata processo
```

Target: `net8.0-windows`. WinExe (não tem console).

## Organização

```
Program.cs                    # entry point [STAThread] → Application.Run(new TrayApplicationContext())
TrayApplicationContext.cs     # ApplicationContext: NotifyIcon, ContextMenuStrip, watchers, timers, ShowDashboard
DashboardForm.cs              # janela WebView2 (painel amigável); init async + runtime check + fallback .md
DataPump.cs                   # lê todos os arquivos do Service e empurra mensagens p/ a página (só com janela aberta)
GeoLookup.cs                  # ip-api.com (país/cidade/ISP) com cache + rate-limit; instância
                              # compartilhada e sempre ativa (alertas + dashboard); ResolveNowAsync p/ toast
Assets/dashboard.html         # SPA (EmbeddedResource) renderizada via NavigateToString
UserInstall.cs                # opt-out por usuário do autostart (HKCU\Software\SecAgent\TrayDisabled);
                              # remoção "deste usuário" sem admin + limpeza do HKCU\Run legado
AgentStatus.cs                # mirror do schema do Service (evita project reference)
AnalysisProgress.cs           # mirror do schema do Service
Models/                       # mirrors: AnalysisResult/Finding/Meta, SecurityEvent, IncidentReport, NetworkSnapshot/Connection
install-tray.ps1              # publish + registra HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SecAgentTray
uninstall-tray.ps1
```

## Painel (DashboardForm + WebView2)

Clique no ícone (esquerdo ou duplo) ou menu "Abrir painel" abre uma única
janela (singleton em `_dashboard`). O **host C# faz toda a leitura de arquivo**
(via `DataPump`); a página WebView2 só renderiza.

- C# → página: `CoreWebView2.PostWebMessageAsJson({type,payload})`. Tipos:
  `status`, `progress`, `report`, `incident`, `events`, `network`, `geo`.
- Página → C#: botões de scan via `chrome.webview.postMessage({cmd})` →
  `DashboardForm` → callback `OnDashboardCommand` → `RequestTrigger` (mesmo
  debounce do menu).
- **Casing**: o Service grava JSON **PascalCase**; a página lê **camelCase**.
  `DataPump.ReadAndCamel<T>` desserializa e re-serializa com `JsonNamingPolicy.
  CamelCase` (idem `OutOpts` para events/geo). Não pular essa normalização.
- WebView2: pacote NuGet `Microsoft.Web.WebView2`; user-data em
  `%LOCALAPPDATA%\SecAgent\WebView2`. Runtime já vem no Win11; se faltar,
  `DashboardForm` cai no fallback de abrir o `.md`.
- `DataPump` só roda enquanto a janela está aberta (Start/Stop); os watchers
  do ícone (abaixo) continuam independentes.

## Padrão arquitetural

`TrayApplicationContext` (ApplicationContext) é o lifecycle owner. Ele cria:

- `NotifyIcon _icon` — ícone na bandeja, com `ContextMenuStrip`
- `System.Windows.Forms.Timer _statusTimer` (10s) — relê `status.json`
- `System.Windows.Forms.Timer _progressTimer` (2s) — só ativo quando há
  progresso; atualiza tooltip elapsed
- `FileSystemWatcher _reportWatcher` — `reports\*.md` → toast no Created
- `FileSystemWatcher _scanWatcher` — `scans\*.json` → toast no Created
  (suprimido durante scan+Claude para evitar duplo toast)
- `FileSystemWatcher _progressWatcher` — `progress.json` Created/Changed/
  Deleted → swap icon + tooltip + transition toast

Tudo é dispatched pelo `ContextMenuStrip.BeginInvoke` quando vem de
worker thread.

## Comunicação com Service

**Só por arquivos** em `C:\ProgramData\SecAgent\`. Sem pipe, sem socket.

| Arquivo | Direção | Quando |
|---|---|---|
| `status.json` | LER | Cada 10s (timer) + após FSWatcher de report |
| `progress.json` | LER | Sempre que muda; existe só durante work ativo |
| `reports\*.md` | OBSERVAR | Toast quando novo |
| `reports\*.json` | LER | Dashboard: findings (report_*) e incidente (incident_*) |
| `scans\*.json` | OBSERVAR | Toast quando novo (só se progress=null/scanning) |
| `events\*.jsonl` | LER (tail) | Dashboard: feed ao vivo (offset em bytes, virada de dia UTC) |
| `network.json` | LER | Dashboard: tabela de conexões (entrada/saída + geo) |
| `alerts\alert_*.json` | OBSERVAR | **Sempre ativo** (não só com painel): toast imediato de conexão externa de entrada, com país (via `GeoLookup`) |
| `triggers\*.trigger` | ESCREVER | Quando user clica menu/botão do painel (debounce 30s) |

## Estado do ícone

| Situação | Icon |
|---|---|
| `status.OverallSeverity="green"` ou ausente | `SystemIcons.Shield` |
| `status.OverallSeverity="yellow"` | `SystemIcons.Warning` |
| `status.OverallSeverity="red"` | `SystemIcons.Error` |
| Progresso ativo (qualquer estado) | `SystemIcons.Information` (azul "busy") |

Campo `_severityIcon` guarda o ícone "idle" (driven by status.json). Quando
`OnProgressFileEvent` dispara, `_icon.Icon` vira `Information`; quando
`OnProgressFileDeleted` dispara, restaura `_severityIcon`.

`RefreshStatus()` só toca `_icon.Icon` quando `_currentProgress is null` —
caso contrário deixa o busy icon em paz.

## Gotchas críticos

1. **FileSystemWatcher dispara em worker thread.** Tocar `NotifyIcon` daí
   crashea silenciosamente. Sempre fazer:
   ```csharp
   if (_icon.ContextMenuStrip?.InvokeRequired == true) {
       _icon.ContextMenuStrip.BeginInvoke(() => OnX(sender, e));
       return;
   }
   ```
2. **`NotifyIcon.Text` cap em 127 chars** (era 63 em .NET Framework).
   Sempre truncar tooltip antes de atribuir.
3. **`ShowBalloonTip` no Windows 10/11** automaticamente vira toast moderno
   no Action Center. Não precisa `Microsoft.Toolkit.Uwp.Notifications` nem
   nenhuma dep extra.
4. **Mirrors de records** (AgentStatus, AnalysisProgress) **devem casar com
   o Service** (mesmas propriedades e nomes). Project reference seria mais
   limpo mas puxa dependências do service (WMI etc). Optei por duplicação
   mínima.
5. **`progress.json` pode estar mid-write** quando watcher dispara. Read
   com retry curto (3 tentativas × 80ms) em `OnProgressFileEvent`.
6. **install-tray.ps1 NÃO precisa admin** — escreve em `HKCU` e roda como
   usuário. Se exigir admin, algo quebrou.
7. **Não publish enquanto o tray está rodando** — `install-tray.ps1` mata
   o processo antes do `dotnet publish` justamente por isso.

## Adicionar novo menu item

Em `BuildMenu()`:
```csharp
menu.Items.Add("Nova ação", null, (_, _) => DoSomething());
```

Para um trigger novo:
1. Adicionar constante `private const string MyTrigger = "my.trigger";`
2. Item de menu chama `RequestTrigger(MyTrigger, "Mensagem do toast inicial...")`
3. **Implementar o handler no Service** (`SecAgent.Service/Triggers/TriggerWatcher.cs`)
   — caso contrário o trigger será deletado sem ação.

## Adicionar novo watcher

Padrão (em ctor):
```csharp
try {
    _myWatcher = new FileSystemWatcher(SomeDir, "pattern") {
        EnableRaisingEvents = true,
        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
    };
    _myWatcher.Created += OnMyEvent;
} catch { /* dir may not exist yet — ok */ }
```

Handler precisa do invoke required check (vide gotcha #1) e do `Dispose()`
em `Dispose(bool disposing)`.

## Debug

Modo dev: `dotnet run`. Tray aparece, mantenha o terminal aberto para
exceptions não capturadas. Ctrl+C mata. Logging vai pro Application Event
Log se houver crash.

Para validar comunicação com Service: tem que estar `Get-Service SecAgent`
rodando. Sem ele, `status.json` não aparece e tray fica em "carregando..."
forever.
