# SecAgent.Installer — CLAUDE.md

Instalador distribuível do SecAgent baseado em **Inno Setup 6**. Gera um
`SecAgent-Setup.exe` único que instala Service + Tray como binários
**self-contained** (sem precisar de .NET na máquina alvo), registra o Windows
Service, configura o token do Claude e o autostart do Tray.

> Veja `..\CLAUDE.md` para visão geral da solution e auth do Claude.

Diferente dos scripts `deploy.ps1` / `install-*.ps1` (que assumem o repo em
`C:\Projetos\SecAgent` e o .NET SDK instalado), este projeto produz um pacote
para máquina limpa. Não é código C# — é um `.iss` (Pascal scripting) + um
`.ps1` de build.

## Arquivos

```
SecAgent.iss          # script Inno Setup: [Setup] [Files] [Registry] [Run] [Code]
build-installer.ps1   # publish self-contained win-x64 + compila o .iss (ISCC.exe)
assets/SecAgent.ico   # (opcional) icone; referencie via SetupIconFile no .iss
output/               # SecAgent-Setup.exe gerado (gitignored)
publish/              # binarios publicados Service/ e Tray/ (gitignored)
```

## Build

```powershell
# Requer .NET 8 SDK e Inno Setup 6 (ISCC.exe).
# winget install JRSoftware.InnoSetup
.\build-installer.ps1   # -> output\SecAgent-Setup.exe
```

O script publica `SecAgent.Service` e `SecAgent.Tray` com
`-r win-x64 --self-contained true` (≈70MB cada) e chama o ISCC. O
`SecAgent.Spike` **não** entra (descartável).

## O que o instalador faz (em runtime, como admin/UAC)

0. **`PrepareToInstall` (antes de copiar [Files])**: para o serviço
   (`sc stop` + espera `STOPPED` via `WaitServiceStopped`) e mata o Tray
   (`taskkill /im SecAgent.Tray.exe /f /t`). Sem isso, `SecAgent.Service.exe`
   (travado pelo serviço LocalSystem, que roda em qualquer login) e
   `SecAgent.Tray.exe` ficam locked e a sobrescrita falha com "acesso negado"
   — clássico ao reinstalar por outro login do Windows.
1. Copia `publish\Service\*` → `{app}\Service` e `publish\Tray\*` → `{app}\Tray`
   (`{app}` = `C:\Program Files\SecAgent`).
2. **Página custom de Claude** (`CreateCustomPage` após a seleção de diretório):
   - Detecta o `claude.exe` (`%USERPROFILE%\.local\bin\claude.exe`, depois PATH)
     com campo editável + botão Procurar.
   - Token: **colar** existente (valida prefixo `sk-ant-oat`), **gerar** (botão
     "Abrir terminal" → `claude setup-token` num terminal real/interativo, o
     usuário cola o token impresso no campo), ou **pular**.
3. Pós-install (`CurStepChanged(ssPostInstall)`):
   - **Patcha** `Claude.ExePath` no `{app}\Service\appsettings.json` com o
     caminho detectado (substitui o default `C:\Users\adria\.local\bin\...`).
   - Grava o token em **Machine scope** via `setx /M`
     (`CLAUDE_CODE_OAUTH_TOKEN`).
   - Registra o serviço: `sc.exe create SecAgent ... obj= LocalSystem` +
     `description` + `failure` (mesmos parâmetros do `SecAgent.Service\deploy.ps1`)
     e dá `sc start`.
   - Autostart do Tray: `HKLM\...\Run\SecAgentTray` (via `[Registry]`) — vale
     para **todos os usuários** (padrão de mercado p/ serviço machine-wide + UI
     por usuário). Também limpa o valor legado em `HKCU\...\Run` (instalações
     antigas) e zera o opt-out `HKCU\Software\SecAgent\TrayDisabled` do usuário
     que roda o setup (reinstalar = "voltar ao padrão").
   - Inicia o Tray como usuário (`[Run]` com `runasoriginaluser`).
4. **Uninstall completo** (`CurUninstallStepChanged`, admin, todos os usuários):
   para+deleta o serviço, mata o Tray, remove o autostart HKLM (via
   `uninsdeletevalue`). **Pergunta** se também remove `C:\ProgramData\SecAgent\`
   (histórico) + o token Machine scope; default = preservar (Não).
5. **Remoção por usuário** (sem admin): NÃO é o desinstalador do Inno — é o item
   de menu "Remover SecAgent deste usuário" no Tray, que grava
   `HKCU\Software\SecAgent\TrayDisabled=1` (honrado pelo Tray no startup) e mata
   só a cópia do login atual. O serviço machine-wide continua. Ver
   `SecAgent.Tray\UserInstall.cs`.

## Gotchas / caveats

1. **Geração do `setup-token`**: o botão "Abrir terminal" roda
   `claude setup-token` num terminal **real e interativo** via
   `ExecAsOriginalUser` (`cmd /k`, sem redirecionar saída) — DESelevado, no
   contexto do usuário logado (`%USERPROFILE%`/PATH/navegador/credenciais
   corretos). O usuário copia o `sk-ant-oat...` impresso e cola no campo; a
   validação (prefixo) é a mesma do "colar token". **Não** há mais scrape de
   stdout (a versão antiga redirecionava p/ arquivo → terminal preto, sem TTY,
   e o claude não exibia o fluxo). Requer **Inno Setup 6.1+** (por causa de
   `ExecAsOriginalUser`); fallback seria `Exec` com `cmd /k` (visível, mas
   elevado).
2. **`claude.exe` + LocalSystem**: o serviço roda como LocalSystem, então o
   `ExePath` patchado precisa ser um caminho absoluto legível/executável por
   ele. Um `claude.exe` em `C:\Users\<user>\.local\bin` funciona; mover ou
   desinstalar o CLI quebra a análise (`File.Exists` falha em `ClaudeAnalyzer`).
3. **Autostart em HKLM (não HKCU)**: o `[Registry]` grava o Run em
   `HKLM\...\Run`, então o Tray sobe para **qualquer** usuário que logar —
   imune a "instalou com admin diferente do usuário final". A escolha por
   usuário fica no opt-out `HKCU\Software\SecAgent\TrayDisabled` (item de menu
   do Tray), não na presença/ausência da chave de autostart.
4. **`GetEnv('USERPROFILE')`**: idem — reflete o usuário do processo de setup.
   Em elevação same-user é o esperado.
5. **WebView2 Runtime**: o Tray usa WebView2 (Evergreen). Win11 já traz; Win10
   pode não ter. O Tray tem fallback (não bloqueia), mas o dashboard só
   renderiza com o runtime. Considerar bundlear o Evergreen Bootstrapper se for
   alvo Win10.
6. **`setx` vs broadcast**: `setx /M` grava no registro e faz broadcast de
   `WM_SETTINGCHANGE`; o `sc start` seguinte sobe o serviço já com a env var no
   ambiente. Espelha o comportamento do `update-token.ps1` + `Restart-Service`.
7. **Self-contained obrigatório aqui**: o `.iss` empacota a pasta `publish`
   inteira. Se trocar para framework-dependent, a máquina alvo precisaria do
   .NET 8 Desktop Runtime — fora do escopo deste pacote.

## Versão

Bump `#define AppVersion` no topo do `.iss` a cada release. O `AppId` (GUID) é
fixo — não mude, senão o Windows trata como produto novo (não atualiza o
anterior).
