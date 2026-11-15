; NetInventory Windows installer (Inno Setup 6). Build with installer\build.ps1, which
; downloads the bundled Python, PostgreSQL and WinSW into installer\build\ first.

#define AppName "NetInventory"
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#define Build "build"

[Setup]
AppId={{6B0E3B53-6A3E-4C55-9C0B-7A1E2D6F4E11}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=NetInventory
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=output
OutputBaseFilename=NetInventory-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#AppName}
CloseApplications=no
SetupLogging=yes

[Tasks]
Name: "dameware"; Description: "Install the DameWare launcher on this PC (makes the Remote control buttons open DameWare Mini Remote Control)"; Flags: unchecked

[Files]
Source: "{#Build}\python\*"; DestDir: "{app}\python"; Flags: recursesubdirs ignoreversion
Source: "..\netinv\*"; DestDir: "{app}\app\netinv"; Excludes: "__pycache__,*.pyc"; Flags: recursesubdirs ignoreversion
Source: "..\config.example.toml"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "..\agent\*"; DestDir: "{app}\agent"; Flags: recursesubdirs ignoreversion
Source: "{#Build}\winsw\WinSW-x64.exe"; DestDir: "{app}\service"; DestName: "NetInventory.exe"; Flags: ignoreversion
Source: "{#Build}\pgsql\*"; DestDir: "{app}\pgsql"; Flags: recursesubdirs ignoreversion; Check: UseBundledPg
Source: "scripts\*"; DestDir: "{app}\scripts"; Flags: ignoreversion
; DameWare launcher: always shipped for GPO deployment, installed on this PC only if the task is ticked.
Source: "..\tools\dameware\*"; DestDir: "{app}\tools\dameware"; Flags: ignoreversion
Source: "..\tools\dameware\Open-DameWare.ps1"; DestDir: "{commonappdata}\{#AppName}"; Flags: ignoreversion; Tasks: dameware
; Prerequisite: Microsoft Visual C++ 2015-2022 runtime (PostgreSQL and some Python wheels need it).
Source: "{#Build}\redist\vc_redist.x64.exe"; DestDir: "{tmp}"; Check: NeedsVcRedist

[Dirs]
Name: "{commonappdata}\{#AppName}"
Name: "{commonappdata}\{#AppName}\logs"

[Registry]
Root: HKLM; Subkey: "SOFTWARE\Classes\dameware"; ValueType: string; ValueName: ""; ValueData: "URL:DameWare Remote Control (NetInventory)"; Flags: uninsdeletekey; Tasks: dameware
Root: HKLM; Subkey: "SOFTWARE\Classes\dameware"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""; Tasks: dameware
Root: HKLM; Subkey: "SOFTWARE\Classes\dameware\shell\open\command"; ValueType: string; ValueName: ""; \
  ValueData: """{sys}\WindowsPowerShell\v1.0\powershell.exe"" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{commonappdata}\{#AppName}\Open-DameWare.ps1"" ""%1"""; Tasks: dameware

[Icons]
Name: "{group}\Open NetInventory dashboard"; Filename: "http://localhost:{code:GetPort}/"
Name: "{group}\Edit configuration"; Filename: "notepad.exe"; Parameters: """{commonappdata}\{#AppName}\config.toml"""
Name: "{group}\Restart NetInventory service"; Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Restart-Service NetInventory"""
Name: "{group}\Load demo data"; Filename: "{app}\python\python.exe"; Parameters: "-m netinv demo"; WorkingDir: "{app}\app"
Name: "{group}\DameWare launcher for GPO"; Filename: "{app}\tools\dameware"
Name: "{group}\Logs folder"; Filename: "{commonappdata}\{#AppName}\logs"
Name: "{group}\Uninstall NetInventory"; Filename: "{uninstallexe}"

[Run]
Filename: "http://localhost:{code:GetPort}/"; Description: "Open the NetInventory dashboard"; Flags: postinstall shellexec nowait skipifsilent

[UninstallRun]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\uninstall.ps1"" -InstallDir ""{app}"""; \
  Flags: runhidden waituntilterminated; RunOnceId: "RemoveServices"

[Code]
var
  DbPage: TInputOptionWizardPage;
  ExistingPage: TInputQueryWizardPage;
  WebPage: TInputQueryWizardPage;
  IsUpgrade: Boolean;      { NetInventory is already set up here: keep its database, config and port }
  PrevMode, PrevPort: String;

function NeedsVcRedist: Boolean;
var
  Installed: Cardinal;
begin
  Result := not (RegQueryDWordValue(HKLM64, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Installed', Installed) and (Installed = 1));
end;

function UseBundledPg: Boolean;
begin
  if IsUpgrade then
    Result := PrevMode = 'bundled'
  else
    Result := DbPage.SelectedValueIndex = 0;
end;

procedure InitializeWizard;
var
  DataDir: String;
begin
  DataDir := ExpandConstant('{commonappdata}\{#AppName}');
  IsUpgrade := FileExists(DataDir + '\config.toml');
  PrevMode := GetPreviousData('DbMode', '');
  if PrevMode = '' then
    if DirExists(DataDir + '\pgdata') then PrevMode := 'bundled' else PrevMode := 'existing';
  PrevPort := GetPreviousData('Port', '');
  DbPage := CreateInputOptionPage(wpSelectDir, 'Database',
    'Where should NetInventory store its data?',
    'NetInventory uses PostgreSQL. Choose a bundled local server or one you already run.',
    True, False);
  DbPage.Add('Install a bundled PostgreSQL on this computer (recommended)');
  DbPage.Add('Use an existing PostgreSQL server');
  DbPage.SelectedValueIndex := 0;

  ExistingPage := CreateInputQueryPage(DbPage.ID, 'Existing PostgreSQL server',
    'Enter the connection details.',
    'The database must already exist, and the user needs rights to create tables and views in it.');
  ExistingPage.Add('Server (host name or IP):', False);
  ExistingPage.Add('Port:', False);
  ExistingPage.Add('Database name:', False);
  ExistingPage.Add('User name:', False);
  ExistingPage.Add('Password:', True);
  ExistingPage.Values[1] := '5432';
  ExistingPage.Values[2] := 'netinv';
  ExistingPage.Values[3] := 'netinv';

  WebPage := CreateInputQueryPage(ExistingPage.ID, 'Dashboard',
    'Choose the web port and the dashboard password.',
    'You sign in to the dashboard as "admin" with this password. ' +
    'AD, WinRM and SNMP settings go in the configuration file after setup (Start menu > NetInventory > Edit configuration).');
  WebPage.Add('Web port:', False);
  WebPage.Add('Dashboard password for "admin":', True);
  WebPage.Add('Confirm password:', True);
  WebPage.Values[0] := '8080';
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  if IsUpgrade then
    Result := (PageID = DbPage.ID) or (PageID = ExistingPage.ID) or (PageID = WebPage.ID)
  else
    Result := (PageID = ExistingPage.ID) and UseBundledPg;
end;

{ Upgrades from versions that didn't record the port: read it from the service definition. }
function PortFromService: String;
var
  Xml: AnsiString;
  S: String;
  I: Integer;
begin
  Result := '8080';
  if LoadStringFromFile(ExpandConstant('{app}\service\NetInventory.xml'), Xml) then
  begin
    S := String(Xml);
    I := Pos('--port ', S);
    if I > 0 then
    begin
      S := Copy(S, I + 7, 6);
      I := 1;
      while (I <= Length(S)) and (S[I] >= '0') and (S[I] <= '9') do I := I + 1;
      if I > 1 then Result := Copy(S, 1, I - 1);
    end;
  end;
end;

{ Stop the running services so their files can be replaced. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Result := '';
  if IsUpgrade then
    Exec('powershell.exe', '-NoProfile -ExecutionPolicy Bypass -Command "Stop-Service NetInventory -Force -ErrorAction SilentlyContinue; ' +
         'Stop-Service NetInventory-PostgreSQL -Force -ErrorAction SilentlyContinue; Start-Sleep 2"', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  P: Integer;
begin
  Result := True;
  if CurPageID = ExistingPage.ID then
  begin
    if (Trim(ExistingPage.Values[0]) = '') or (Trim(ExistingPage.Values[2]) = '') or (Trim(ExistingPage.Values[3]) = '') then
    begin
      MsgBox('Enter the server, database name and user name.', mbError, MB_OK);
      Result := False;
    end;
  end;
  if CurPageID = WebPage.ID then
  begin
    P := StrToIntDef(WebPage.Values[0], 0);
    if (P < 1) or (P > 65535) then
    begin
      MsgBox('Enter a port between 1 and 65535.', mbError, MB_OK);
      Result := False;
    end
    else if Length(WebPage.Values[1]) < 8 then
    begin
      MsgBox('Use a dashboard password of at least 8 characters.', mbError, MB_OK);
      Result := False;
    end
    else if WebPage.Values[1] <> WebPage.Values[2] then
    begin
      MsgBox('The passwords do not match.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

{ Values passed on the command line are wrapped in double quotes; strip any the user typed. }
function Clean(S: String): String;
begin
  Result := S;
  StringChangeEx(Result, '"', '', True);
end;

function UrlEncode(S: String): String;
var
  I: Integer;
  C: Char;
begin
  Result := '';
  for I := 1 to Length(S) do
  begin
    C := S[I];
    if ((C >= 'A') and (C <= 'Z')) or ((C >= 'a') and (C <= 'z')) or ((C >= '0') and (C <= '9')) or (C = '-') or (C = '_') or (C = '.') or (C = '~') then
      Result := Result + C
    else
      Result := Result + '%' + Format('%.2x', [Ord(C)]);
  end;
end;

function GetDbMode(Param: String): String;
begin
  if UseBundledPg then Result := 'bundled' else Result := 'existing';
end;

function GetDbUrl(Param: String): String;
begin
  if UseBundledPg then
    Result := ''
  else
    Result := 'postgresql+psycopg://' + UrlEncode(ExistingPage.Values[3]) + ':' + UrlEncode(ExistingPage.Values[4]) +
              '@' + Clean(Trim(ExistingPage.Values[0])) + ':' + Clean(Trim(ExistingPage.Values[1])) + '/' + UrlEncode(Trim(ExistingPage.Values[2]));
end;

function GetPort(Param: String): String;
begin
  if IsUpgrade then
  begin
    if PrevPort = '' then PrevPort := PortFromService;
    Result := PrevPort;
  end
  else if WebPage = nil then Result := '8080' else Result := Clean(Trim(WebPage.Values[0]));
end;

procedure RegisterPreviousData(PreviousDataKey: Integer);
begin
  SetPreviousData(PreviousDataKey, 'DbMode', GetDbMode(''));
  SetPreviousData(PreviousDataKey, 'Port', GetPort(''));
end;

{ Secrets go to a temp file (deleted by the script) instead of the command line, so they
  never appear in the setup log or the process list. }
procedure CurStepChanged(CurStep: TSetupStep);
var
  ParamFile, Lines, Cmd: String;
  Code: Integer;
begin
  if CurStep <> ssPostInstall then Exit;
  if NeedsVcRedist then
  begin
    WizardForm.StatusLabel.Caption := 'Installing Microsoft Visual C++ runtime...';
    { 0 = ok, 1638 = newer version already present, 3010 = ok but reboot needed }
    if not Exec(ExpandConstant('{tmp}\vc_redist.x64.exe'), '/install /quiet /norestart', '', SW_HIDE, ewWaitUntilTerminated, Code)
       or not ((Code = 0) or (Code = 1638) or (Code = 3010)) then
      MsgBox('Installing the Visual C++ runtime failed (code ' + IntToStr(Code) + '). The database may not start.', mbError, MB_OK);
  end;
  ParamFile := ExpandConstant('{tmp}\netinv-params.txt');
  Lines := 'InstallDir=' + ExpandConstant('{app}') + #13#10 +
           'DataDir=' + ExpandConstant('{commonappdata}\{#AppName}') + #13#10 +
           'DbMode=' + GetDbMode('') + #13#10 +
           'DbUrl=' + GetDbUrl('') + #13#10 +
           'Port=' + GetPort('') + #13#10 +
           'UiPassword=' + WebPage.Values[1] + #13#10;
  if IsUpgrade then Lines := Lines + 'Upgrade=1' + #13#10;
  SaveStringToFile(ParamFile, Lines, False);
  WizardForm.StatusLabel.Caption := 'Setting up the database and Windows services...';
  Cmd := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\scripts\postinstall.ps1') + '" -ParamFile "' + ParamFile + '"';
  if not Exec('powershell.exe', Cmd, '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    MsgBox('Setup finished copying files, but configuring the services failed (code ' + IntToStr(Code) + ').' + #13#10 +
           'See ' + ExpandConstant('{commonappdata}\{#AppName}\logs\install.log') + ' for details.', mbError, MB_OK);
  DeleteFile(ParamFile);
end;
