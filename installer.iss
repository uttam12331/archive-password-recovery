; Inno Setup script for Archive Password Recovery
; Build:  "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss
; Output: Output\ArchiveRecovery-Setup.exe

#define AppName "Archive Password Recovery"
#define AppVer  "1.0.0"
#define AppExe  "ArchiveRecovery.exe"

[Setup]
AppName={#AppName}
AppVersion={#AppVer}
AppPublisher=Uttam Limbani (open source, MIT)
DefaultDirName={autopf}\ArchiveRecovery
DefaultGroupName=Archive Password Recovery
UninstallDisplayIcon={app}\{#AppExe}
OutputDir=Output
OutputBaseFilename=ArchiveRecovery-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=appicon.ico
ArchitecturesInstallIn64BitMode=x64compatible
LicenseFile=LICENSE

[Files]
; ships the whole built folder (exe + _internal + hashcat + tools)
Source: "dist\ArchiveRecovery\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Archive Password Recovery"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Archive Password Recovery"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch Archive Password Recovery"; Flags: nowait postinstall skipifsilent
