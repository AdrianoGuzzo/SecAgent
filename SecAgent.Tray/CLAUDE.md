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
Program.cs                    # entry point [STAThread] → Application.Run(new TrayApplicationContext())  (glue)
TrayApplicationContext.cs     # glue: NotifyIcon, menu, watchers, timers, ShowDashboard — aplica o Core
DashboardForm.cs              # glue: janela WebView2; init async + runtime check + fallback .md
TokenSetupForm.cs             # glue: janela "Configurar IA" (setup-token + gravação elevada)
DataPump.cs                   # lê os arquivos do Service e empurra mensagens p/ a página (só com janela aberta)
GeoLookup.cs                  # IGeoLookup: ip-api.com com cache em disco, negative-cache em memória,
                              # rate-limit 40/min; instância compartilhada (alertas + dashboard)
TokenSetup.cs                 # token configurado? / localizar claude.exe (fontes injetáveis)
UserInstall.cs                # glue: opt-out por usuário do autostart (HKCU\Software\SecAgent\TrayDisabled)
Core/                         # lógica pura e testada (sem WinForms):
  DashboardCommand.cs         #   DashboardCommandParser: {cmd} da página → comando tipado
  TriggerRequester.cs         #   grava triggers\*.trigger com debounce → Ok/Debounced/Denied/Failed
  TrayStatePresenter.cs       #   ícone, tooltips (≤127), toasts, progresso órfão (IsStale)
  JsonFileReader.cs           #   leitura com retry ASSÍNCRONO (nunca Thread.Sleep na UI)
  EventsTail.cs               #   tail do events\*.jsonl por offset em bytes (só linhas completas)
  DashboardAssets.cs          #   inline de CSS/JS embutidos no dashboard.html
  WebMessage.cs               #   envelope {type,payload} + fila de mensagens até o WebView2 ficar pronto
  TokenCommands.cs            #   script PowerShell elevado (-EncodedCommand) + comando do setup-token
  AiPrefsStore.cs             #   último modelo/esforço escolhido (%LOCALAPPDATA%\SecAgent\ai-prefs.json)
Assets/dashboard.html         # SPA (EmbeddedResource) renderizada via NavigateToString
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
  `JsonFileReader.ReadAsCamelAsync<T>` desserializa no modelo de
  `SecAgent.Contracts` e re-serializa com `JsonDefaults.CamelCase`. Não pular
  essa normalização.
- WebView2: pacote NuGet `Microsoft.Web.WebView2`; user-data em
  `%LOCALAPPDATA%\SecAgent\WebView2`. Runtime já vem no Win11; se faltar,
  `DashboardForm` cai no fallback de abrir o `.md`.
- `DataPump` só roda enquanto a janela está aberta (Start/Stop); os watchers
  do ícone (abaixo) continuam independentes.

## JavaScript do painel (`Assets/js/`)

O JS do dashboard é **orientado a objetos com classes ES6** — sem estado global
mutável, sem `function`/`let` soltos no escopo de módulo. **Todo `.js` novo deve
seguir esse padrão**:

- **`core.js` é a infraestrutura compartilhada** e carrega primeiro. Expõe o
  namespace único `window.SecAgent` e as classes utilitárias:
  - `Severity.of(s)` — severidade textual → `{label, cls, color}`.
  - `Format.esc/flag/time` — escape de HTML (XSS), bandeira de país, hora pt-BR.
  - `Bridge` — encapsula `window.chrome.webview` (`send(cmd)` / `onMessage`).
  - `MessageRouter` — despacha cada `{type, payload}` do host para o handler da
    aba dona. Instância em `SecAgent.router`.
  - `Tabs` — troca de abas do `<nav>`.
- **Cada aba/painel é uma única classe `XPanel`** (`ResumoPanel`, `ConexoesPanel`,
  `EventosPanel`, …) no seu próprio arquivo:
  - Estado vive em campos de instância (`this._x`), **nunca** em variáveis globais.
  - Constantes/configs como **`static`** da classe (`static MAX_FEED = 200`).
  - O `constructor` inicializa estado e faz wiring de DOM (helpers `_bindXxx`).
  - Um método `register(router)` assina os tipos de mensagem que a aba trata
    via `router.register('tipo', p => this.onTipo(p))` (ou `registerAll({...})`).
  - Handlers públicos `onTipo(payload)`; render/helpers privados com prefixo `_`.
  - **Bootstrap no fim do arquivo**: `new XPanel().register(SecAgent.router);`.
- **Reutilize os utilitários** — chame `Format.esc/flag/time` e `Severity.of`;
  não redefina helpers nem acesse `chrome.webview` direto (use `cmd(...)` ou o
  `Bridge`).
- Comentários em **pt-BR**, explicando o porquê (mesma densidade do código atual).
- **Registre o arquivo novo em `dashboard.html`** na ordem dos `<script>` —
  sempre **depois de `core.js`** (as classes do core precisam existir antes).

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
  **Renamed**/Deleted → swap icon + tooltip + transition toast
- `FileSystemWatcher` de `alerts\alert_*.json` — toast imediato (sempre ativo)

Tudo é dispatched pelo `ContextMenuStrip.BeginInvoke` (`OnUi`) quando vem de
worker thread. **Regra**: o `TrayApplicationContext` só aplica o resultado do
`TrayStatePresenter`/`TriggerRequester`/`DashboardCommandParser`; qualquer `if`
de regra novo vai para `Core/` com teste.

## Testes

`SecAgent.Tray.Tests` (xUnit + NSubstitute + `FakeTimeProvider`), gate de 80%
de linhas em `[SecAgent.Tray]*`. Glue de WinForms/WebView2/registro é
`[ExcludeFromCodeCoverage]`. `GeoLookup` e `DataPump` têm construtores
`internal` que recebem caminho, `HttpMessageHandler`, `AgentPaths` e
`TimeProvider` — use-os nos testes (nunca a rede ou `C:\ProgramData`).

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
`OnProgressChangedAsync` lê um progresso, `_icon.Icon` vira `Information`;
quando `progress.json` é apagado (`OnProgressDeleted`), restaura `_severityIcon`.

`RefreshStatusAsync()` só toca `_icon.Icon` quando `_currentProgress is null` —
caso contrário deixa o busy icon em paz.

**Progresso órfão**: se o Service cair no meio do scan, `progress.json` fica
para trás. `TrayStatePresenter.IsStale` (> 15 min) faz o Tray voltar ao ícone
de severidade.

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
4. **Modelos vêm de `SecAgent.Contracts`** (referência de projeto, sem
   dependências de WMI etc.). Não recrie mirrors no Tray.
5. **`progress.json` pode estar mid-write** quando watcher dispara. Use
   `JsonFileReader.ReadAsync<T>` (3 tentativas × 80ms, **assíncrono**) — nunca
   `Thread.Sleep` em watcher ou na UI thread.
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
1. Adicionar constante em `SecAgent.Contracts/TriggerNames.cs`
2. Item de menu chama `RequestTrigger(TriggerNames.MyTrigger, "Mensagem do toast inicial...")`
3. **Implementar o handler no Service** (`SecAgent.Service/Triggers/TriggerWatcher.cs`)
   — caso contrário o trigger será deletado sem ação.

## Adicionar novo watcher

Padrão (em ctor), via helper `Watch` — já assina Created **e Renamed**
(escrita atômica do Service) e guarda o watcher para o `Dispose`:
```csharp
Watch(_paths.SomeDir, "pattern", created: e => OnMyEvent(e));
```

Handler que toca UI passa por `OnUi(...)` (vide gotcha #1); leitura de
arquivo com `JsonFileReader` (async).

## Debug

Modo dev: `dotnet run`. Tray aparece, mantenha o terminal aberto para
exceptions não capturadas. Ctrl+C mata. Logging vai pro Application Event
Log se houver crash.

Para validar comunicação com Service: tem que estar `Get-Service SecAgent`
rodando. Sem ele, `status.json` não aparece e tray fica em "carregando..."
forever.
