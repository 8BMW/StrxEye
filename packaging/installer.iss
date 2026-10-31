; Inno Setup script for the Windows installer.
;
;   iscc /DAppVersion=1.0.0 packaging\installer.iss
;
; Expects the PyInstaller output in build\dist\STRX EYE (see strxeye.spec).
; Installs per user by default (no administrator prompt); the user can
; choose an all-users install from the first page.

#ifndef AppVersion
  #error Pass the version: iscc /DAppVersion=1.2.3 packaging\installer.iss
#endif

[Setup]
; Never change AppId: Windows uses it to recognise upgrades of the same app.
AppId={{8C5E2F1A-3B7D-4E9A-9F21-5A6B7C8D9E01}
AppName=STRX EYE
AppVersion={#AppVersion}
AppVerName=STRX EYE {#AppVersion}
AppPublisher=STRX EYE contributors
AppPublisherURL=https://github.com/8BMW/StrxEye
AppSupportURL=https://github.com/8BMW/StrxEye/issues
AppUpdatesURL=https://github.com/8BMW/StrxEye/releases
DefaultDirName={autopf}\STRX EYE
DefaultGroupName=STRX EYE
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\build\installer
OutputBaseFilename=STRX-EYE-Setup-{#AppVersion}
SetupIconFile=strxeye.ico
UninstallDisplayIcon={app}\STRX EYE.exe
UninstallDisplayName=STRX EYE
LicenseFile=..\LICENSE
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Lets the in-app updater replace files while the app is running: the
; Restart Manager closes it first.
CloseApplications=force
ChangesEnvironment=yes

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "Add the strxeye command-line tool to PATH (current user)"; GroupDescription: "Command line:"; Flags: unchecked

[Files]
Source: "..\build\dist\STRX EYE\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Remove files from the previous version so stale libraries are not loaded.
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{group}\STRX EYE"; Filename: "{app}\STRX EYE.exe"
Name: "{group}\Uninstall STRX EYE"; Filename: "{uninstallexe}"
Name: "{autodesktop}\STRX EYE"; Filename: "{app}\STRX EYE.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
; Interactive install: offer to launch. Silent install (used by the in-app
; updater): relaunch the app automatically.
Filename: "{app}\STRX EYE.exe"; Description: "{cm:LaunchProgram,STRX EYE}"; Flags: nowait postinstall skipifsilent
Filename: "{app}\STRX EYE.exe"; Flags: nowait; Check: WizardSilent

[UninstallDelete]
Type: dirifempty; Name: "{app}"

[Code]
function NeedsAddPath(Dir: string): Boolean;
var
  Current: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Current) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Current) + ';') = 0;
end;

procedure RemoveFromPath(Dir: string);
var
  Current, Needle: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Current) then
    exit;
  Needle := ';' + Uppercase(Dir);
  P := Pos(Needle, ';' + Uppercase(Current));
  if P > 0 then
  begin
    { P is 1-based in the ';'-prefixed string, so it maps to P-1 in Current. }
    if P = 1 then
      Delete(Current, 1, Length(Dir) + 1)
    else
      Delete(Current, P - 1, Length(Dir) + 1);
    RegWriteExpandStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Current);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
