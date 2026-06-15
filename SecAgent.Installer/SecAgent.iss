; SecAgent.iss - Inno Setup script para o instalador do SecAgent
; ----------------------------------------------------------------------------
; Gera SecAgent-Setup.exe que instala Service + Tray (self-contained, sem
; precisar de .NET instalado), registra o Windows Service SecAgent, configura
; o token do Claude (CLAUDE_CODE_OAUTH_TOKEN, Machine scope) e o autostart do
; Tray. Compile via SecAgent.Installer\build-installer.ps1 (que publica os
; binarios em publish\Service e publish\Tray antes de chamar o ISCC).
;
; Inno Setup 6.1+ requerido (usa ExecAsOriginalUser).
; winget install JRSoftware.InnoSetup

#define AppName "SecAgent"
#define AppVersion "1.0.0"
#define AppPublisher "Adriano Guzzo"
#define ServiceName "SecAgent"
#define ServiceDisplay "SecAgent (Security monitoring + Claude analysis)"
#define ServiceDesc "Daily Windows security configuration scan with AI-driven analysis via Claude Code subscription. Real-time process/network/eventlog monitoring with ad-hoc incident analysis."
#define TrayRunValue "SecAgentTray"

[Setup]
AppId={{B6E5A1C2-9D4F-4E7A-8B3C-1F2A3B4C5D6E}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayName={#AppName}
; Servico + env var Machine + sc.exe exigem elevacao.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=output
OutputBaseFilename=SecAgent-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Para usar um icone, descomente e coloque o arquivo em assets\SecAgent.ico:
; SetupIconFile=assets\SecAgent.ico

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Binarios publicados pelo build-installer.ps1 (self-contained win-x64).
Source: "publish\Service\*"; DestDir: "{app}\Service"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "publish\Tray\*";    DestDir: "{app}\Tray";    Flags: ignoreversion recursesubdirs createallsubdirs

[Registry]
; Autostart do Tray para o usuario que rodou o setup (HKCU).
; Caveat: com UAC same-user, HKCU continua sendo a hive do usuario -> OK em
; maquina pessoal. Se um admin DIFERENTE instalar, cai na hive errada.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "{#TrayRunValue}"; \
    ValueData: """{app}\Tray\SecAgent.Tray.exe"""; \
    Flags: uninsdeletevalue

[Run]
; Inicia o Tray como o usuario (nao elevado) ao final.
Filename: "{app}\Tray\SecAgent.Tray.exe"; Description: "Iniciar o SecAgent Tray agora"; \
    Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
const
  EnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';
  TokenVar = 'CLAUDE_CODE_OAUTH_TOKEN';

var
  TokenPage: TWizardPage;
  EditClaude: TNewEdit;
  BtnBrowse: TNewButton;
  RbPaste, RbGenerate, RbSkip: TNewRadioButton;
  EditToken: TNewEdit;
  BtnGenTerm: TNewButton;
  LblClaudeStatus: TNewStaticText;
  ClaudeFound: Boolean;
  ResolvedToken: string;   // token final a gravar ('' = pular)
  ResolvedClaude: string;  // caminho do claude.exe a gravar no appsettings ('' = nao mexer)

{ ----- Helpers de deteccao do claude.exe ----- }

function DetectClaude(): string;
var
  Candidate: string;
begin
  Result := '';
  { 1) %USERPROFILE%\.local\bin\claude.exe (instalacao padrao do Claude Code no Windows) }
  Candidate := AddBackslash(GetEnv('USERPROFILE')) + '.local\bin\claude.exe';
  if FileExists(Candidate) then begin
    Result := Candidate;
    exit;
  end;
  { 2) Procurar 'claude.exe' nas pastas do PATH }
  Candidate := '';
  if FileSearch('claude.exe', GetEnv('PATH')) <> '' then begin
    Result := FileSearch('claude.exe', GetEnv('PATH'));
    exit;
  end;
end;

{ ----- Habilita/desabilita controles conforme o radio selecionado ----- }

procedure UpdateTokenControls();
begin
  { O mesmo campo de token serve para "colar" e para "gerar" (o usuario cola
    o token impresso pelo terminal). }
  EditToken.Enabled := RbPaste.Checked or RbGenerate.Checked;
  { Gerar so faz sentido se achamos o claude.exe }
  RbGenerate.Enabled := EditClaude.Text <> '';
  if (not RbGenerate.Enabled) and RbGenerate.Checked then begin
    RbGenerate.Checked := False;
    RbPaste.Checked := True;
    EditToken.Enabled := True;
  end;
  { Botao de abrir o terminal so quando "gerar" esta ativo e ha claude.exe }
  if BtnGenTerm <> nil then
    BtnGenTerm.Enabled := RbGenerate.Checked and (Trim(EditClaude.Text) <> '');
end;

procedure RadioClicked(Sender: TObject);
begin
  UpdateTokenControls();
end;

procedure ClaudeChanged(Sender: TObject);
begin
  UpdateTokenControls();
end;

procedure BrowseClicked(Sender: TObject);
var
  F: string;
begin
  F := EditClaude.Text;
  if GetOpenFileName('Selecione o claude.exe', F, '', 'Executavel (*.exe)|*.exe|Todos (*.*)|*.*', 'exe') then
    EditClaude.Text := F;
end;

{ ----- Abre um terminal real e interativo para 'claude setup-token' ----- }

procedure GenTerminalClicked(Sender: TObject);
var
  Code: Integer;
begin
  if Trim(EditClaude.Text) = '' then begin
    MsgBox('Informe o caminho do claude.exe primeiro.', mbError, MB_OK);
    exit;
  end;
  { 'cmd /k' mantem a janela aberta para o usuario ler/copiar o token e ver
    eventuais erros. ExecAsOriginalUser roda DESelevado, no contexto do
    usuario logado (%USERPROFILE%, PATH, navegador e credenciais do claude
    corretos). ewNoWait: nao trava o wizard enquanto o usuario faz o login.
    Sem redirecionar a saida -> claude tem um TTY real e mostra a URL e os
    prompts (corrige a "tela preta"). }
  ExecAsOriginalUser(ExpandConstant('{cmd}'),
    '/k ""' + Trim(EditClaude.Text) + '" setup-token"',
    '', SW_SHOW, ewNoWait, Code);
  MsgBox('Um terminal foi aberto para o login do Claude.'#13#10 +
         'Conclua o login no navegador, copie o token exibido (sk-ant-oat...) '#13#10 +
         'e cole no campo de token desta tela antes de clicar em Avancar.',
         mbInformation, MB_OK);
end;

{ ----- Monta a pagina custom ----- }

procedure InitializeWizard();
begin
  TokenPage := CreateCustomPage(wpSelectDir,
    'Claude Code', 'Configure o acesso do SecAgent ao Claude Code');

  { Caminho do claude.exe }
  LblClaudeStatus := TNewStaticText.Create(WizardForm);
  LblClaudeStatus.Parent := TokenPage.Surface;
  LblClaudeStatus.Top := 0;
  LblClaudeStatus.Width := TokenPage.SurfaceWidth;
  LblClaudeStatus.Caption := 'Caminho do claude.exe (usado pelo servico para a analise com IA):';

  EditClaude := TNewEdit.Create(WizardForm);
  EditClaude.Parent := TokenPage.Surface;
  EditClaude.Top := LblClaudeStatus.Top + LblClaudeStatus.Height + 4;
  EditClaude.Width := TokenPage.SurfaceWidth - 90;
  EditClaude.OnChange := @ClaudeChanged;

  BtnBrowse := TNewButton.Create(WizardForm);
  BtnBrowse.Parent := TokenPage.Surface;
  BtnBrowse.Top := EditClaude.Top - 1;
  BtnBrowse.Left := EditClaude.Left + EditClaude.Width + 8;
  BtnBrowse.Width := 80;
  BtnBrowse.Caption := 'Procurar...';
  BtnBrowse.OnClick := @BrowseClicked;

  { Radios }
  RbPaste := TNewRadioButton.Create(WizardForm);
  RbPaste.Parent := TokenPage.Surface;
  RbPaste.Top := EditClaude.Top + EditClaude.Height + 18;
  RbPaste.Width := TokenPage.SurfaceWidth;
  RbPaste.Caption := 'Colar um token existente (gere antes com: claude setup-token)';
  RbPaste.OnClick := @RadioClicked;

  EditToken := TNewEdit.Create(WizardForm);
  EditToken.Parent := TokenPage.Surface;
  EditToken.Top := RbPaste.Top + RbPaste.Height + 2;
  EditToken.Left := 16;
  EditToken.Width := TokenPage.SurfaceWidth - 16;
  EditToken.PasswordChar := '#';
  EditToken.Text := '';

  RbGenerate := TNewRadioButton.Create(WizardForm);
  RbGenerate.Parent := TokenPage.Surface;
  RbGenerate.Top := EditToken.Top + EditToken.Height + 14;
  RbGenerate.Width := TokenPage.SurfaceWidth;
  RbGenerate.Caption := 'Gerar agora: abre um terminal para o login e cole o token gerado no campo acima';
  RbGenerate.OnClick := @RadioClicked;

  BtnGenTerm := TNewButton.Create(WizardForm);
  BtnGenTerm.Parent := TokenPage.Surface;
  BtnGenTerm.Top := RbGenerate.Top + RbGenerate.Height + 4;
  BtnGenTerm.Left := 16;
  BtnGenTerm.Width := 240;
  BtnGenTerm.Caption := 'Abrir terminal (claude setup-token)';
  BtnGenTerm.OnClick := @GenTerminalClicked;

  RbSkip := TNewRadioButton.Create(WizardForm);
  RbSkip.Parent := TokenPage.Surface;
  RbSkip.Top := BtnGenTerm.Top + BtnGenTerm.Height + 14;
  RbSkip.Width := TokenPage.SurfaceWidth;
  RbSkip.Caption := 'Pular (configurar depois) - o servico instala, mas a analise com IA fica inativa';
  RbSkip.OnClick := @RadioClicked;

  { Deteccao inicial do claude.exe }
  ResolvedClaude := DetectClaude();
  ClaudeFound := ResolvedClaude <> '';
  EditClaude.Text := ResolvedClaude;
  if ClaudeFound then
    LblClaudeStatus.Caption := 'claude.exe detectado (edite se necessario):'
  else
    LblClaudeStatus.Caption := 'claude.exe NAO encontrado - informe o caminho ou instale o Claude Code CLI:';

  RbPaste.Checked := True;
  UpdateTokenControls();
end;

{ ----- Validacao ao sair da pagina de token ----- }

function NextButtonClick(CurPageID: Integer): Boolean;
var
  T: string;
begin
  Result := True;
  if CurPageID <> TokenPage.ID then exit;

  ResolvedClaude := Trim(EditClaude.Text);

  if RbSkip.Checked then begin
    ResolvedToken := '';
    exit;
  end;

  { Colar e Gerar usam o mesmo campo: em "gerar", o usuario abriu o terminal
    (botao) e colou aqui o token impresso pelo claude setup-token. }
  if RbPaste.Checked or RbGenerate.Checked then begin
    T := Trim(EditToken.Text);
    if T = '' then begin
      if RbGenerate.Checked then
        MsgBox('Cole o token gerado no terminal (botao "Abrir terminal") ou escolha outra opcao.',
               mbError, MB_OK)
      else
        MsgBox('Cole o token ou escolha outra opcao.', mbError, MB_OK);
      Result := False;
      exit;
    end;
    if Pos('sk-ant-oat', T) <> 1 then begin
      if MsgBox('O token nao comeca com "sk-ant-oat" (formato esperado de OAuth). Usar mesmo assim?',
                mbConfirmation, MB_YESNO) <> IDYES then begin
        Result := False;
        exit;
      end;
    end;
    ResolvedToken := T;
    exit;
  end;
end;

{ ----- Patch do appsettings.json: Claude.ExePath -> caminho detectado ----- }

procedure PatchExePath(const FilePath, NewExe: string);
var
  Raw: AnsiString;
  Content, Marker, Escaped, Before, After: string;
  P, Start, Q: Integer;
begin
  if NewExe = '' then exit;
  if not LoadStringFromFile(FilePath, Raw) then exit;
  Content := string(Raw);

  Marker := '"ExePath": "';
  P := Pos(Marker, Content);
  if P = 0 then exit;

  Start := P + Length(Marker);
  { Acha a aspa de fechamento do valor }
  Q := Start;
  while (Q <= Length(Content)) and (Content[Q] <> '"') do
    Inc(Q);
  if Q > Length(Content) then exit;

  { JSON exige backslash escapado }
  Escaped := NewExe;
  StringChangeEx(Escaped, '\', '\\', True);

  Before := Copy(Content, 1, Start - 1);
  After := Copy(Content, Q, Length(Content));  { comeca na aspa de fechamento }
  Content := Before + Escaped + After;

  SaveStringToFile(FilePath, AnsiString(Content), False);
end;

{ ----- Registro/inicio do servico ----- }

procedure RunSc(const Params: string);
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure InstallService();
var
  SvcExe: string;
begin
  SvcExe := ExpandConstant('{app}\Service\SecAgent.Service.exe');

  { Remove instalacao anterior, se houver }
  RunSc('stop {#ServiceName}');
  RunSc('delete {#ServiceName}');
  Sleep(1000);

  RunSc('create {#ServiceName} binPath= "' + SvcExe + '" start= auto obj= LocalSystem DisplayName= "{#ServiceDisplay}"');
  RunSc('description {#ServiceName} "{#ServiceDesc}"');
  RunSc('failure {#ServiceName} reset= 86400 actions= restart/60000/restart/60000/restart/60000');
  RunSc('start {#ServiceName}');
end;

{ ----- Espera o servico chegar em STOPPED (ou inexistir), liberando o lock ----- }

function WaitServiceStopped(TimeoutMs: Integer): Boolean;
var
  TmpFile, Content: string;
  Raw: AnsiString;
  Code, Elapsed: Integer;
begin
  Result := False;
  TmpFile := ExpandConstant('{tmp}\sc_query.txt');
  Elapsed := 0;
  while Elapsed < TimeoutMs do begin
    { Exec nao captura stdout; redireciona via cmd para um arquivo temp }
    Exec(ExpandConstant('{cmd}'),
         '/c sc query {#ServiceName} > "' + TmpFile + '" 2>&1',
         '', SW_HIDE, ewWaitUntilTerminated, Code);
    if LoadStringFromFile(TmpFile, Raw) then begin
      Content := string(Raw);
      { STOPPED = parado; 1060 = servico nao existe -> nada a esperar }
      if (Pos('STOPPED', Content) > 0) or (Pos('1060', Content) > 0) then begin
        Result := True;
        break;
      end;
    end else begin
      Result := True;
      break;
    end;
    Sleep(500);
    Elapsed := Elapsed + 500;
  end;
  DeleteFile(TmpFile);
end;

{ ----- Antes de copiar [Files]: parar servico + Tray que travam os .exe ----- }

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Result := '';
  { 1) Parar o servico (LocalSystem) que segura SecAgent.Service.exe. Roda
       independente do login, por isso a reinstalacao cross-login dava
       "acesso negado" na sobrescrita. }
  RunSc('stop {#ServiceName}');
  WaitServiceStopped(15000);
  { 2) Matar o Tray (qualquer sessao) que segura SecAgent.Tray.exe }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/im SecAgent.Tray.exe /f /t',
       '', SW_HIDE, ewWaitUntilTerminated, Code);
  { 3) Folga para liberar os handles antes da copia }
  Sleep(1000);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  if CurStep <> ssPostInstall then exit;

  { 1) Patch do appsettings.json com o caminho real do claude.exe }
  PatchExePath(ExpandConstant('{app}\Service\appsettings.json'), ResolvedClaude);

  { 2) Token em Machine scope (setx /M grava no registro e faz broadcast) }
  if ResolvedToken <> '' then
    Exec(ExpandConstant('{sys}\setx.exe'),
         TokenVar + ' "' + ResolvedToken + '" /M', '', SW_HIDE, ewWaitUntilTerminated, Code);

  { 3) Registrar e iniciar o servico }
  InstallService();
end;

{ ----- Desinstalacao: parar/remover servico e Tray (preserva ProgramData + token) ----- }

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
begin
  if CurUninstallStep <> usUninstall then exit;

  Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/im SecAgent.Tray.exe /f', '', SW_HIDE, ewWaitUntilTerminated, Code);
  { ProgramData (historico) e CLAUDE_CODE_OAUTH_TOKEN sao preservados de proposito. }
end;
