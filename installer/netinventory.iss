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
; Always offer the install folder on a new install; upgrades skip it in ShouldSkipPage and keep the folder in use.
DisableDirPage=no
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
; Wizard helper that checks whether a port is free; extracted to {tmp} when needed, never installed.
Source: "portcheck.ps1"; Flags: dontcopy

[Dirs]
Name: "{code:GetDataDir}"
Name: "{code:GetDataDir}\logs"

[Registry]
Root: HKLM; Subkey: "SOFTWARE\Classes\dameware"; ValueType: string; ValueName: ""; ValueData: "URL:DameWare Remote Control (NetInventory)"; Flags: uninsdeletekey; Tasks: dameware
Root: HKLM; Subkey: "SOFTWARE\Classes\dameware"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""; Tasks: dameware
Root: HKLM; Subkey: "SOFTWARE\Classes\dameware\shell\open\command"; ValueType: string; ValueName: ""; \
  ValueData: """{sys}\WindowsPowerShell\v1.0\powershell.exe"" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{commonappdata}\{#AppName}\Open-DameWare.ps1"" ""%1"""; Tasks: dameware

[Icons]
Name: "{group}\Open NetInventory dashboard"; Filename: "https://localhost:{code:GetPort}/"
Name: "{group}\Edit configuration"; Filename: "notepad.exe"; Parameters: """{code:GetDataDir}\config.toml"""
Name: "{group}\Restart NetInventory service"; Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Restart-Service NetInventory"""
Name: "{group}\Load demo data"; Filename: "{app}\python\python.exe"; Parameters: "-m netinv demo"; WorkingDir: "{app}\app"
Name: "{group}\DameWare launcher for GPO"; Filename: "{app}\tools\dameware"
Name: "{group}\Logs folder"; Filename: "{code:GetDataDir}\logs"
Name: "{group}\Uninstall NetInventory"; Filename: "{uninstallexe}"

[Run]
Filename: "https://localhost:{code:GetPort}/"; Description: "Open the NetInventory dashboard"; Flags: postinstall shellexec nowait skipifsilent

; Everything setup put in the install folder goes, including files created there afterwards (Python caches,
; service wrapper logs, packages repaired from the bundled wheels). Only setup's own subfolders are deleted,
; not the whole folder, in case it was installed into a folder that holds other files; the folder itself is
; removed when nothing else is left. Setup keeps the data folders outside the install folder.
[UninstallDelete]
Type: filesandordirs; Name: "{app}\python"
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\service"
Type: filesandordirs; Name: "{app}\pgsql"
Type: filesandordirs; Name: "{app}\scripts"
Type: filesandordirs; Name: "{app}\agent"
Type: filesandordirs; Name: "{app}\tools"
Type: dirifempty; Name: "{app}"

[UninstallRun]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\uninstall.ps1"" -InstallDir ""{app}"""; \
  Flags: runhidden waituntilterminated; RunOnceId: "RemoveServices"

[Code]
var
  DataPage: TInputDirWizardPage;
  DbPage: TInputOptionWizardPage;
  PgDirPage: TInputDirWizardPage;
  PgPage: TInputQueryWizardPage;
  ExistingPage: TInputQueryWizardPage;
  WebPage: TInputQueryWizardPage;
  IsUpgrade: Boolean;      { NetInventory is already set up here: keep its database, config and ports }
  PrevMode, PrevPort, PrevPgPort, ConfPgPort: String;
  PrevDataDir, PrevPgData: String;   { where an existing install keeps its data and its bundled database }
  AutoPgDir: String;                 { database folder last filled in from the data folder, so a typed one isn't overwritten }
  PortCheckReady: Boolean;

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

{ The port an existing bundled cluster listens on, from its postgresql.conf (the last "port =" line wins,
  as in PostgreSQL itself). Empty when there is no cluster or no port line. }
function PortFromPgConf(PgDir: String): String;
var
  Lines: TArrayOfString;
  I, J: Integer;
  S: String;
begin
  Result := '';
  if not LoadStringsFromFile(AddBackslash(PgDir) + 'postgresql.conf', Lines) then Exit;
  for I := 0 to GetArrayLength(Lines) - 1 do
  begin
    S := Trim(Lines[I]);
    if (Copy(S, 1, 4) = 'port') and (Length(S) > 4) and ((S[5] = ' ') or (S[5] = '=') or (S[5] = #9)) then
    begin
      S := Trim(Copy(S, 5, Length(S)));
      if (S <> '') and (S[1] = '=') then
      begin
        S := Trim(Copy(S, 2, Length(S)));
        J := 1;
        while (J <= Length(S)) and (S[J] >= '0') and (S[J] <= '9') do J := J + 1;
        if J > 1 then Result := Copy(S, 1, J - 1);
      end;
    end;
  end;
end;

{ The data folder named by the machine-wide NETINV_CONFIG variable that setup writes (empty if unset). }
function DataDirFromEnvironment: String;
var
  V: String;
begin
  Result := '';
  if RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'NETINV_CONFIG', V) and (Trim(V) <> '') then
    Result := ExtractFileDir(Trim(V));
end;

{ The data folder: the existing one on upgrades, otherwise the one chosen in the wizard. }
function GetDataDirValue: String;
begin
  if IsUpgrade then
    Result := PrevDataDir
  else
    Result := RemoveBackslashUnlessRoot(Trim(DataPage.Values[0]));
end;

function GetDataDir(Param: String): String;
begin
  Result := GetDataDirValue;
end;

{ The bundled database folder, kept as it is on upgrades. }
function GetPgData(Param: String): String;
begin
  if IsUpgrade then
    Result := PrevPgData
  else
    Result := RemoveBackslashUnlessRoot(Trim(PgDirPage.Values[0]));
end;

procedure InitializeWizard;
var
  DefaultDataDir: String;
begin
  { Find an existing install's data: recorded by setup (0.6+), else the NETINV_CONFIG variable, else the
    folder every version before 0.6 used. }
  DefaultDataDir := ExpandConstant('{commonappdata}\{#AppName}');
  PrevDataDir := GetPreviousData('DataDir', '');
  if (PrevDataDir = '') or not FileExists(AddBackslash(PrevDataDir) + 'config.toml') then PrevDataDir := DataDirFromEnvironment;
  if (PrevDataDir = '') or not FileExists(AddBackslash(PrevDataDir) + 'config.toml') then PrevDataDir := DefaultDataDir;
  IsUpgrade := FileExists(AddBackslash(PrevDataDir) + 'config.toml');
  PrevPgData := GetPreviousData('PgData', '');
  if PrevPgData = '' then PrevPgData := AddBackslash(PrevDataDir) + 'pgdata';
  PrevMode := GetPreviousData('DbMode', '');
  if PrevMode = '' then
    if DirExists(PrevPgData) then PrevMode := 'bundled' else PrevMode := 'existing';
  PrevPort := GetPreviousData('Port', '');
  if IsUpgrade then ConfPgPort := PortFromPgConf(PrevPgData) else ConfPgPort := PortFromPgConf(AddBackslash(DefaultDataDir) + 'pgdata');
  PrevPgPort := GetPreviousData('PgPort', '');
  if PrevPgPort = '' then PrevPgPort := ConfPgPort;
  if PrevPgPort = '' then PrevPgPort := '5442';    { what versions before 0.5 always used }
  DataPage := CreateInputDirPage(wpSelectDir, 'Data folder',
    'Where should NetInventory keep its data?',
    'This folder holds the configuration, logs, HTTPS certificate and encryption key (and, by default, the bundled database). ' +
    'Setup restricts it to Administrators and SYSTEM, so choose a new or empty folder, not one shared with other files. ' +
    'Uninstalling NetInventory leaves this folder in place.',
    False, '');
  DataPage.Add('Data folder:');
  { A rerun after a setup that didn't finish offers the folders chosen last time. }
  DataPage.Values[0] := GetPreviousData('DataDir', DefaultDataDir);

  DbPage := CreateInputOptionPage(DataPage.ID, 'Database',
    'Where should NetInventory store its data?',
    'NetInventory uses PostgreSQL. Choose a bundled local server or one you already run.',
    True, False);
  DbPage.Add('Install a bundled PostgreSQL on this computer (recommended)');
  DbPage.Add('Use an existing PostgreSQL server');
  DbPage.SelectedValueIndex := 0;

  PgDirPage := CreateInputDirPage(DbPage.ID, 'Bundled PostgreSQL',
    'Where should the bundled database keep its files?',
    'Put it on a drive with room to grow and, ideally, regular backups. Choose a new or empty folder: ' +
    'setup restricts it to Administrators, SYSTEM and the database service.',
    False, '');
  PgDirPage.Add('Database folder:');
  AutoPgDir := AddBackslash(DataPage.Values[0]) + 'pgdata';
  PgDirPage.Values[0] := GetPreviousData('PgData', AutoPgDir);

  PgPage := CreateInputQueryPage(PgDirPage.ID, 'Bundled PostgreSQL',
    'Choose the port for the bundled database.',
    'The bundled PostgreSQL only listens on this computer (localhost). The default, 5442, avoids the usual ' +
    'PostgreSQL port 5432 so it never clashes with another PostgreSQL server here. Setup checks that the port is free.');
  PgPage.Add('Database port:', False);
  { A cluster left in the data folder by an earlier install keeps its port. }
  if ConfPgPort <> '' then PgPage.Values[0] := ConfPgPort else PgPage.Values[0] := '5442';

  ExistingPage := CreateInputQueryPage(PgPage.ID, 'Existing PostgreSQL server',
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
    Result := (PageID = wpSelectDir) or (PageID = DataPage.ID) or (PageID = DbPage.ID) or (PageID = PgDirPage.ID) or
              (PageID = PgPage.ID) or (PageID = ExistingPage.ID) or (PageID = WebPage.ID)
  else if UseBundledPg then
    Result := PageID = ExistingPage.ID
  else
    Result := (PageID = PgDirPage.ID) or (PageID = PgPage.ID);
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

{ Asks portcheck.ps1 who listens on Port. Returns True when another program has it; a NetInventory
  process from this install folder (a reinstall over a running copy) doesn't count. Suggest gets the
  next free port, skipping Avoid. If the check itself can't run, the port counts as free: the
  post-install script checks again before it starts anything. }
function PortTaken(Port, Avoid: Integer; var Owner, Suggest: String): Boolean;
var
  OutFile, Cmd, Dir: String;
  Code: Integer;
  Arr: TArrayOfString;
begin
  Result := False;
  Owner := '';
  Suggest := '';
  if not PortCheckReady then
  begin
    ExtractTemporaryFile('portcheck.ps1');
    PortCheckReady := True;
  end;
  OutFile := ExpandConstant('{tmp}\portcheck-out.txt');
  DeleteFile(OutFile);
  Cmd := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{tmp}\portcheck.ps1') + '" -Port ' + IntToStr(Port) +
         ' -Avoid ' + IntToStr(Avoid) + ' -Out "' + OutFile + '"';
  WizardForm.NextButton.Enabled := False;
  try
    if Exec('powershell.exe', Cmd, '', SW_HIDE, ewWaitUntilTerminated, Code) and LoadStringsFromFile(OutFile, Arr) and (GetArrayLength(Arr) >= 2) then
    begin
      Owner := Trim(Arr[0]);
      Suggest := Trim(Arr[1]);
      Dir := Lowercase(AddBackslash(WizardDirValue));
      Result := (Owner <> '') and (Pos(Dir, Lowercase(Owner)) <> 1);
    end;
  finally
    WizardForm.NextButton.Enabled := True;
    DeleteFile(OutFile);
  end;
end;

{ Checks the port typed in Page.Values[Index]. If another program has it, says which one and offers the next
  free port; Yes puts that port in the field and carries on, No stays on the page. }
function PortFreeOrSwitched(Page: TInputQueryWizardPage; Index, Avoid: Integer; What: String): Boolean;
var
  Port: Integer;
  Owner, Suggest: String;
begin
  Result := True;
  Port := StrToInt(Trim(Page.Values[Index]));
  if not PortTaken(Port, Avoid, Owner, Suggest) then Exit;
  if Suggest = '' then
  begin
    MsgBox('Port ' + IntToStr(Port) + ' is already used by:' + #13#10 + Owner + #13#10#13#10 +
           'Setup will not touch it. Enter another ' + What + ' port.', mbError, MB_OK);
    Result := False;
  end
  else if MsgBox('Port ' + IntToStr(Port) + ' is already used by:' + #13#10 + Owner + #13#10#13#10 +
                 'Setup will not touch it. Use port ' + Suggest + ' for the ' + What + ' instead?' + #13#10#13#10 +
                 'Yes uses ' + Suggest + '. No lets you type a different port.', mbConfirmation, MB_YESNO) = IDYES then
    Page.Values[Index] := Suggest
  else
    Result := False;
end;

{ True when Dir holds nothing but the names in Ignore ('|'-separated, lower case, with '|' at both ends). }
function DirEmpty(Dir, Ignore: String): Boolean;
var
  F: TFindRec;
begin
  Result := True;
  if FindFirst(AddBackslash(Dir) + '*', F) then
  try
    repeat
      if (F.Name <> '.') and (F.Name <> '..') and (Pos('|' + Lowercase(F.Name) + '|', Ignore) = 0) then Result := False;
    until (not Result) or (not FindNext(F));
  finally
    FindClose(F);
  end;
end;

{ True when Inner is Outer or a folder inside it. }
function IsWithin(Inner, Outer: String): Boolean;
begin
  Result := Pos(Lowercase(AddBackslash(Outer)), Lowercase(AddBackslash(Inner))) = 1;
end;

{ Checks a folder typed on the data or database page. Marker is the file that shows the folder already
  belongs to NetInventory (config.toml, PG_VERSION): such a folder is reused as it is. Any other folder
  must be new or empty, because setup removes inherited permissions from it. }
function FolderOk(var Dir: String; Marker, What: String): Boolean;
begin
  Result := False;
  Dir := RemoveBackslashUnlessRoot(Trim(Dir));
  if (Length(Dir) < 3) or (Dir[2] <> ':') or (Dir[3] <> '\') then
    MsgBox('Enter a full path on a local drive for the ' + What + ', such as D:\NetInventory.', mbError, MB_OK)
  else if Length(Dir) = 3 then
    MsgBox('Choose a folder for the ' + What + ', not the root of a drive.', mbError, MB_OK)
  else if IsWithin(Dir, WizardDirValue) or IsWithin(WizardDirValue, Dir) then
    MsgBox('Keep the ' + What + ' separate from the install folder (' + WizardDirValue + '), not inside it or around it.', mbError, MB_OK)
  { Files a NetInventory setup that failed part way may have left (logs, password file, certificate, the
    DameWare launcher, which always goes to ProgramData\NetInventory) don't make the folder "in use". }
  else if DirExists(Dir) and not FileExists(AddBackslash(Dir) + Marker) and
          not DirEmpty(Dir, '|logs|pgdata|.pg-password|tls.crt|tls.key|updates|catalog|open-dameware.ps1|') then
    MsgBox(Dir + ' already has other files in it.' + #13#10#13#10 +
           'Setup restricts the ' + What + ' to Administrators and SYSTEM, which would lock other people out of those files. ' +
           'Choose a new or empty folder.', mbError, MB_OK)
  else
    Result := True;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  P, Pg: Integer;
  Dir: String;
begin
  Result := True;
  if CurPageID = DataPage.ID then
  begin
    Dir := DataPage.Values[0];
    Result := FolderOk(Dir, 'config.toml', 'data folder');
    if Result then
    begin
      DataPage.Values[0] := Dir;
      if FileExists(AddBackslash(Dir) + 'config.toml') then
        MsgBox('This folder has data from an earlier NetInventory install. Setup will keep its configuration ' +
               '(the dashboard password you enter later replaces the old one).', mbInformation, MB_OK);
      { Keep the database with the data unless a different folder was typed for it. }
      if CompareText(PgDirPage.Values[0], AutoPgDir) = 0 then
      begin
        AutoPgDir := AddBackslash(Dir) + 'pgdata';
        PgDirPage.Values[0] := AutoPgDir;
      end;
    end;
  end;
  if CurPageID = PgDirPage.ID then
  begin
    Dir := PgDirPage.Values[0];
    Result := FolderOk(Dir, 'PG_VERSION', 'database folder');
    if Result and IsWithin(GetDataDirValue, Dir) then
    begin
      MsgBox('The database folder can''t contain the data folder. Put it inside the data folder or somewhere else.', mbError, MB_OK);
      Result := False;
    end;
    if Result and FileExists(AddBackslash(Dir) + 'PG_VERSION') then
    begin
      if not FileExists(AddBackslash(GetDataDirValue) + '.pg-password') then
      begin
        MsgBox('This folder holds a database from an earlier install, but its password is kept in that install''s data folder, ' +
               'which isn''t the one chosen. Go back and choose that data folder too, or pick an empty database folder.', mbError, MB_OK);
        Result := False;
      end
      else
      begin
        MsgBox('This folder has a database from an earlier NetInventory install. Setup will keep it.', mbInformation, MB_OK);
        if PortFromPgConf(Dir) <> '' then PgPage.Values[0] := PortFromPgConf(Dir);
      end;
    end;
    if Result then PgDirPage.Values[0] := Dir;
  end;
  if CurPageID = PgPage.ID then
  begin
    P := StrToIntDef(Trim(PgPage.Values[0]), 0);
    if (P < 1) or (P > 65535) then
    begin
      MsgBox('Enter a port between 1 and 65535.', mbError, MB_OK);
      Result := False;
    end
    else
      Result := PortFreeOrSwitched(PgPage, 0, StrToIntDef(Trim(WebPage.Values[0]), 0), 'database');
  end;
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
    P := StrToIntDef(Trim(WebPage.Values[0]), 0);
    if UseBundledPg then Pg := StrToIntDef(Trim(PgPage.Values[0]), 0) else Pg := 0;
    if (P < 1) or (P > 65535) then
    begin
      MsgBox('Enter a port between 1 and 65535.', mbError, MB_OK);
      Result := False;
    end
    else if P = Pg then
    begin
      MsgBox('Port ' + IntToStr(P) + ' is already chosen for the bundled database. Use a different web port.', mbError, MB_OK);
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
    end
    else
      Result := PortFreeOrSwitched(WebPage, 0, Pg, 'dashboard');
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

{ Port of the bundled PostgreSQL. Upgrades keep the one in use; empty for an existing server. }
function GetPgPort(Param: String): String;
begin
  if not UseBundledPg then
    Result := ''
  else if IsUpgrade then
    Result := PrevPgPort
  else
    Result := Clean(Trim(PgPage.Values[0]));
end;

procedure RegisterPreviousData(PreviousDataKey: Integer);
begin
  SetPreviousData(PreviousDataKey, 'DbMode', GetDbMode(''));
  SetPreviousData(PreviousDataKey, 'Port', GetPort(''));
  SetPreviousData(PreviousDataKey, 'DataDir', GetDataDirValue);
  if UseBundledPg then
  begin
    SetPreviousData(PreviousDataKey, 'PgPort', GetPgPort(''));
    SetPreviousData(PreviousDataKey, 'PgData', GetPgData(''));
  end;
end;

{ Secrets go to a temp file (deleted by the script) instead of the command line, so they
  never appear in the setup log or the process list. }
procedure CurStepChanged(CurStep: TSetupStep);
var
  ParamFile, Lines, Cmd: String;
  Code: Integer;
  Arr: TArrayOfString;
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
           'DataDir=' + GetDataDirValue + #13#10 +
           'PgData=' + GetPgData('') + #13#10 +
           'DbMode=' + GetDbMode('') + #13#10 +
           'DbUrl=' + GetDbUrl('') + #13#10 +
           'Port=' + GetPort('') + #13#10 +
           'PgPort=' + GetPgPort('') + #13#10 +
           'UiPassword=' + WebPage.Values[1] + #13#10;
  if IsUpgrade then Lines := Lines + 'Upgrade=1' + #13#10;
  SetArrayLength(Arr, 1);
  Arr[0] := Lines;
  SaveStringsToUTF8File(ParamFile, Arr, False);   { UTF-8, so any character in the password survives }
  WizardForm.StatusLabel.Caption := 'Setting up the database and Windows services...';
  Cmd := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\scripts\postinstall.ps1') + '" -ParamFile "' + ParamFile + '"';
  if not Exec('powershell.exe', Cmd, '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    MsgBox('Setup finished copying files, but configuring the services failed (code ' + IntToStr(Code) + ').' + #13#10 +
           'See ' + AddBackslash(GetDataDirValue) + 'logs\install.log for details.', mbError, MB_OK);
  DeleteFile(ParamFile);
end;

{ ---------------------------------------------------------------- uninstall }

var
  UninstDataDir, UninstPgData: String;
  DeleteData: Boolean;

{ Setup's saved values live in the uninstall key as "Inno Setup CodeFile: <name>". }
function UninstallValue(Name: String): String;
begin
  Result := '';
  RegQueryStringValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{6B0E3B53-6A3E-4C55-9C0B-7A1E2D6F4E11}_is1',   { AppId + _is1 }
    'Inno Setup CodeFile: ' + Name, Result);
end;

{ Find the data folders before uninstall.ps1 removes NETINV_CONFIG, and ask once whether to delete them.
  The default is to keep them, so an uninstall by mistake doesn't wipe the inventory. }
function InitializeUninstall: Boolean;
var
  Msg: String;
begin
  Result := True;
  UninstDataDir := UninstallValue('DataDir');
  if UninstDataDir = '' then UninstDataDir := DataDirFromEnvironment;
  if UninstDataDir = '' then UninstDataDir := ExpandConstant('{commonappdata}\{#AppName}');
  UninstPgData := '';
  if UninstallValue('DbMode') <> 'existing' then
  begin
    UninstPgData := UninstallValue('PgData');
    if UninstPgData = '' then UninstPgData := AddBackslash(UninstDataDir) + 'pgdata';
  end;
  DeleteData := False;
  if not DirExists(UninstDataDir) and ((UninstPgData = '') or not DirExists(UninstPgData)) then Exit;
  Msg := 'Also delete NetInventory''s data?' + #13#10#13#10 + '  ' + UninstDataDir + #13#10;
  if (UninstPgData <> '') and DirExists(UninstPgData) and not IsWithin(UninstPgData, UninstDataDir) then
    Msg := Msg + '  ' + UninstPgData + #13#10;
  Msg := Msg + #13#10 + 'This is the inventory database, configuration, keys and logs, and it can''t be undone.' + #13#10#13#10 +
         'Yes deletes it all. No keeps it, so installing NetInventory again picks up where it left off.';
  DeleteData := SuppressibleMsgBox(Msg, mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  { By now the services are stopped and removed, so nothing holds the database files open. }
  if (CurUninstallStep = usPostUninstall) and DeleteData then
  begin
    { Never a drive root, whatever the registry says. }
    if (Length(UninstPgData) > 3) and DirExists(UninstPgData) then DelTree(UninstPgData, True, True, True);
    if (Length(UninstDataDir) > 3) and DirExists(UninstDataDir) then DelTree(UninstDataDir, True, True, True);
  end;
end;
