Unicode true
!include "LogicLib.nsh"

!define APP "Imon"
; Keep the uninstall record identity for upgrades of the original installer.
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\InfraMonitorDesktop"
!define LEGACY_INSTALL_DIR "$LOCALAPPDATA\Programs\Infra Monitor"
!define RUNTIME_KEY "Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

Name "${APP}"
Icon "imon.ico"
UninstallIcon "imon.ico"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\Imon"
RequestExecutionLevel user
SetCompressor /SOLID lzma
VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=1033 "ProductName" "${APP}"
VIAddVersionKey /LANG=1033 "FileDescription" "Imon Desktop Installer"
VIAddVersionKey /LANG=1033 "FileVersion" "${VERSION}"

Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Function .onInit
  SetRegView 32
  ReadRegStr $0 HKLM "${RUNTIME_KEY}" "pv"
  ${If} $0 != ""
  ${AndIf} $0 != "0.0.0.0"
    Return
  ${EndIf}
  ReadRegStr $0 HKCU "${RUNTIME_KEY}" "pv"
  ${If} $0 != ""
  ${AndIf} $0 != "0.0.0.0"
    Return
  ${EndIf}
  MessageBox MB_OK|MB_ICONSTOP "Microsoft Edge WebView2 Evergreen Runtime is required. Install it from Microsoft and then retry." /SD IDOK
  SetErrorLevel 1
  Abort
FunctionEnd

Section "Install"
  SetShellVarContext current
  SetOutPath "$INSTDIR"
  File "payload/imon-desktop.exe"
  File "payload/WebView-LICENSE.txt"
  File "payload/backup-and-restore.md"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateShortcut "$SMPROGRAMS\Imon.lnk" "$INSTDIR\imon-desktop.exe"
  ReadRegStr $0 HKCU "${UNINSTALL_KEY}" "UninstallString"
  ${If} $0 == '$\"${LEGACY_INSTALL_DIR}\Uninstall.exe$\"'
    Delete "$SMPROGRAMS\Infra Monitor.lnk"
    Delete "${LEGACY_INSTALL_DIR}\infra-monitor-desktop.exe"
    ${If} $INSTDIR != "${LEGACY_INSTALL_DIR}"
      Delete "${LEGACY_INSTALL_DIR}\WebView-LICENSE.txt"
      Delete "${LEGACY_INSTALL_DIR}\backup-and-restore.md"
      Delete "${LEGACY_INSTALL_DIR}\Uninstall.exe"
      RMDir "${LEGACY_INSTALL_DIR}"
    ${EndIf}
  ${EndIf}
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "${APP}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\imon-desktop.exe,0"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetShellVarContext current
  Delete "$SMPROGRAMS\Imon.lnk"
  Delete "$INSTDIR\imon-desktop.exe"
  Delete "$INSTDIR\WebView-LICENSE.txt"
  Delete "$INSTDIR\backup-and-restore.md"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "${UNINSTALL_KEY}"
SectionEnd
