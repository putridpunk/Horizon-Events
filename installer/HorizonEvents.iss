; Inno Setup script: builds dist\HorizonEvents-Setup.exe from dist\HorizonEvents.exe.
; Per-user install by default (no administrator rights), with an optional all-users install.
#define AppName "Horizon Events"
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#define AppExe "HorizonEvents.exe"

[Setup]
AppId={{6F3B8E52-4C1D-4A7B-9E0A-5D2C7B1F8A34}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=putridpunk
AppPublisherURL=https://github.com/putridpunk/Horizon-Events
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
LicenseFile=..\LICENSE
SetupIconFile=..\assets\horizon.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
OutputDir=..\dist
OutputBaseFilename=HorizonEvents-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "startmenuicon"; Description: "Create a &Start menu shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "..\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: startmenuicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
// The app can stay running in the system tray, where closing its window only hides it. Stop it before files are
// replaced or removed, so an update or uninstall does not fail on a file that is in use.
procedure StopApp;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}	askkill.exe'), '/IM {#AppExe} /F', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopApp;
  Result := '';
end;

function InitializeUninstall: Boolean;
begin
  StopApp;
  Result := True;
end;

function DataDir: String;
begin
  Result := ExpandConstant('{localappdata}\HorizonEvents');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and DirExists(DataDir) and not UninstallSilent then
    if MsgBox('Also delete your Horizon Events data (collected events, alerts and settings)?' + #13#10 + #13#10 +
              DataDir + #13#10 + #13#10 + 'This cannot be undone. Choose No to keep it.',
              mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(DataDir, True, True, True);
end;
