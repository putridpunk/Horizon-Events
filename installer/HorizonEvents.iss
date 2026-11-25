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
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM {#AppExe} /F', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopApp;
  Result := '';
end;

// Uninstalling never closes the app for the user: if a copy is running (even hidden in the tray) the uninstall stops
// here, with an error, and nothing has been removed. The app holds this named marker for as long as it runs.
function InitializeUninstall: Boolean;
begin
  Result := True;
  if CheckForMutexes('HorizonEvents.Running') then
  begin
    MsgBox('Horizon Events is still running.' + #13#10 + #13#10 +
           'Close all instances of Horizon Events before uninstalling it. If it is in the system tray, ' +
           'right-click its icon and choose Quit. Nothing has been removed.',
           mbError, MB_OK);
    Result := False;
  end;
end;

function DataDir: String;
begin
  Result := ExpandConstant('{localappdata}\HorizonEvents');
end;

// Uninstalling removes everything the app put on the computer: the program, its shortcuts, its data (events, alerts,
// settings, quarantine, logs), its start-with-Windows entry and the firewall rules it added. The program does the
// part that only it knows about (--uninstall-cleanup); the data folder is also removed here as a safety net.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    if Exec(ExpandConstant('{app}\{#AppExe}'), '--uninstall-cleanup', '', SW_HIDE, ewWaitUntilTerminated, Code) then
      if (Code and 2) <> 0 then
        SuppressibleMsgBox('Some Windows Firewall rules added by Horizon Events (named "Horizon Events block ...") ' +
          'could not be removed because administrator permission was not granted. You can delete them in ' +
          'Windows Defender Firewall with Advanced Security.', mbInformation, MB_OK, IDOK);
  end;
  if (CurUninstallStep = usPostUninstall) and DirExists(DataDir) then
    DelTree(DataDir, True, True, True);
end;
