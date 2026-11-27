; Freeton VPN Windows x64 NSIS Installer Script
; Builds dist/FreetonVPN-Setup-x64.exe from compiled Rust binaries and staged WireGuard DLLs.

Unicode true

!ifndef APP_VERSION
  !define APP_VERSION "3.0.3"
!endif
!ifndef APP_VI_VERSION
  !define APP_VI_VERSION "${APP_VERSION}.0"
!endif

!define APP_NAME "Freeton VPN"
!define APP_PUBLISHER "pishun"
!define APP_EXE "FreetonVPN.exe"
!define SERVICE_EXE "FreetonVPNService.exe"
!define BROKER_SERVICE_NAME "FreetonVPNService"
!define TUNNEL_SERVICE_NAME "WireGuardTunnel$$FreetonVPN"
!define UNINSTALL_REG_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\FreetonVPN"
!define APP_REG_KEY "Software\FreetonVPN"

Name "${APP_NAME}"
OutFile "..\..\dist\FreetonVPN-Setup-x64.exe"
InstallDir "$PROGRAMFILES64\FreetonVPN"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${APP_VI_VERSION}"
VIAddVersionKey "ProductName" "${APP_NAME}"
VIAddVersionKey "CompanyName" "${APP_PUBLISHER}"
VIAddVersionKey "FileDescription" "${APP_NAME} x64 Setup"
VIAddVersionKey "FileVersion" "${APP_VI_VERSION}"
VIAddVersionKey "ProductVersion" "${APP_VERSION}"
VIAddVersionKey "LegalCopyright" "Copyright (c) 2026 ${APP_PUBLISHER}"

!include "MUI2.nsh"
!include "x64.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

!define MUI_ICON "..\..\freeton_icon.ico"
!define MUI_UNICON "..\..\freeton_icon.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${APP_NAME}"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchAppUnelevated

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

!macro DEFINE_PROCESS_HELPERS UN_PREFIX
  ; Checks if process image name in $R6 is running; sets $0 = 1 (running) or 0 (not running).
  Function ${UN_PREFIX}IsProcessRunning
    nsExec::ExecToStack '"$SYSDIR\cmd.exe" /C ""$SYSDIR\tasklist.exe" /FI "IMAGENAME eq $R6" /FO CSV /NH | "$SYSDIR\findstr.exe" /I "$R6""'
    Pop $0
    Pop $1
    ${If} $0 == 0
      StrCpy $0 1
    ${Else}
      StrCpy $0 0
    ${EndIf}
  FunctionEnd

  ; Polls up to $R5 iterations of 250ms for process in $R6 to exit cleanly;
  ; terminates with taskkill /F only if still alive after the grace period.
  Function ${UN_PREFIX}WaitOrKillProcess
    ${If} $R5 > 0
      ${For} $R4 1 $R5
        Call ${UN_PREFIX}IsProcessRunning
        ${If} $0 == 0
          ${Break}
        ${EndIf}
        Sleep 250
      ${Next}
    ${EndIf}

    Call ${UN_PREFIX}IsProcessRunning
    ${If} $0 == 1
      DetailPrint "Closing running $R6..."
      nsExec::ExecToStack '"$SYSDIR\taskkill.exe" /F /IM $R6'
      Pop $0
      Pop $1
      ${For} $R4 1 12
        Call ${UN_PREFIX}IsProcessRunning
        ${If} $0 == 0
          ${Break}
        ${EndIf}
        Sleep 250
      ${Next}
      Sleep 200
    ${EndIf}
  FunctionEnd
!macroend

!macro DEFINE_SERVICE_HELPERS UN_PREFIX
  ; Stops service named in $R8 and waits up to 15 seconds for STOPPED or absent ($R9 = 0 ok, 1 timeout).
  Function ${UN_PREFIX}StopServiceInR8
    nsExec::ExecToStack '"$SYSDIR\sc.exe" query "$R8"'
    Pop $0
    Pop $1
    ${If} $0 != 0
      StrCpy $R9 0
      Return
    ${EndIf}

    DetailPrint "Stopping service $R8..."
    nsExec::ExecToStack '"$SYSDIR\sc.exe" stop "$R8"'
    Pop $0
    Pop $1

    StrCpy $R9 1
    ${For} $R7 1 30
      nsExec::ExecToStack '"$SYSDIR\sc.exe" query "$R8"'
      Pop $0
      Pop $1
      ${If} $0 != 0
        StrCpy $R9 0
        ${Break}
      ${EndIf}

      nsExec::ExecToStack '"$SYSDIR\cmd.exe" /C ""$SYSDIR\sc.exe" query "$R8" | "$SYSDIR\findstr.exe" /C:"STOPPED""'
      Pop $0
      Pop $1
      ${If} $0 == 0
        StrCpy $R9 0
        ${Break}
      ${EndIf}
      Sleep 500
    ${Next}
  FunctionEnd

  ; Deletes service named in $R8 if present and waits up to 3 seconds for SCM removal.
  Function ${UN_PREFIX}DeleteServiceInR8
    nsExec::ExecToStack '"$SYSDIR\sc.exe" query "$R8"'
    Pop $0
    Pop $1
    ${If} $0 != 0
      Return
    ${EndIf}

    nsExec::ExecToStack '"$SYSDIR\sc.exe" delete "$R8"'
    Pop $0
    Pop $1
    ${For} $R7 1 10
      nsExec::ExecToStack '"$SYSDIR\sc.exe" query "$R8"'
      Pop $0
      Pop $1
      ${If} $0 != 0
        ${Break}
      ${EndIf}
      Sleep 300
    ${Next}
  FunctionEnd

  ; Waits up to 5 seconds for FreetonVPNService.exe to release its process lock after SERVICE_STOPPED,
  ; falling back to taskkill /F only if the process does not exit in time.
  Function ${UN_PREFIX}WaitServiceProcessesStopped
    StrCpy $R6 "${SERVICE_EXE}"
    StrCpy $R5 20
    Call ${UN_PREFIX}WaitOrKillProcess
  FunctionEnd
!macroend

!insertmacro DEFINE_PROCESS_HELPERS ""
!insertmacro DEFINE_SERVICE_HELPERS ""
!insertmacro DEFINE_PROCESS_HELPERS "un."
!insertmacro DEFINE_SERVICE_HELPERS "un."

; Launches FreetonVPN.exe via explorer.exe so it inherits the interactive user's medium-integrity token.
Function LaunchAppUnelevated
  ${If} ${FileExists} "$INSTDIR\${APP_EXE}"
    Exec '"$WINDIR\explorer.exe" "$INSTDIR\${APP_EXE}"'
  ${EndIf}
FunctionEnd

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP|MB_OK "${APP_NAME} requires 64-bit Windows (x64)."
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all

  ; Read 64-bit InstallDir explicitly after SetRegView 64 (preserving explicit /D= overrides).
  ReadRegStr $0 HKLM "${APP_REG_KEY}" "InstallDir"
  ${If} $0 != ""
  ${AndIf} $INSTDIR == "$PROGRAMFILES64\FreetonVPN"
    StrCpy $INSTDIR "$0"
  ${EndIf}
FunctionEnd

Function .onInstSuccess
  ${If} ${Silent}
    Call LaunchAppUnelevated
  ${EndIf}
FunctionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
  ${If} $INSTDIR == ""
    ReadRegStr $0 HKLM "${APP_REG_KEY}" "InstallDir"
    ${If} $0 != ""
      StrCpy $INSTDIR "$0"
    ${EndIf}
  ${EndIf}
FunctionEnd

Section "Install" SEC_MAIN
  SetRegView 64
  SetShellVarContext all

  ; 1. Stop active WireGuard tunnel, broker service, service processes, and GUI process cleanly before overwriting files.
  StrCpy $R8 "${TUNNEL_SERVICE_NAME}"
  Call StopServiceInR8
  ${If} $R9 != 0
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "Timed out waiting for ${TUNNEL_SERVICE_NAME} to stop. Please disconnect VPN and retry."
    ${EndIf}
    SetErrorLevel 1
    Abort
  ${EndIf}
  Call DeleteServiceInR8

  StrCpy $R8 "${BROKER_SERVICE_NAME}"
  Call StopServiceInR8
  ${If} $R9 != 0
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "Timed out waiting for ${BROKER_SERVICE_NAME} to stop. Please retry installation."
    ${EndIf}
    SetErrorLevel 1
    Abort
  ${EndIf}

  Call WaitServiceProcessesStopped

  StrCpy $R6 "${APP_EXE}"
  ${If} ${Silent}
    StrCpy $R5 10
  ${Else}
    StrCpy $R5 0
  ${EndIf}
  Call WaitOrKillProcess

  ; 2. Install binaries, staged WireGuard DLLs, and icon into 64-bit install directory.
  SetOutPath "$INSTDIR"
  File "..\..\rust\target\release\${APP_EXE}"
  File "..\..\rust\target\release\${SERVICE_EXE}"
  File "..\..\rust\assets\bin\tunnel.dll"
  File "..\..\rust\assets\bin\wireguard.dll"
  File "..\..\freeton_icon.ico"

  ; 3. Register/update FreetonVPNService and grant Interactive Users pipe/service rights.
  DetailPrint "Installing and starting ${BROKER_SERVICE_NAME}..."
  nsExec::ExecToStack '"$INSTDIR\${SERVICE_EXE}" --install'
  Pop $0
  Pop $1
  ${If} $0 != 0
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "Failed to install ${BROKER_SERVICE_NAME} (exit code $0).$\r$\n$1"
    ${EndIf}
    SetErrorLevel 1
    Abort
  ${EndIf}

  ; 4. Write Start Menu shortcuts and 64-bit Add/Remove Programs entries.
  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\freeton_icon.ico" 0
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\Uninstall ${APP_NAME}.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\freeton_icon.ico" 0

  WriteUninstaller "$INSTDIR\uninstall.exe"

  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0

  WriteRegStr HKLM "${APP_REG_KEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "Publisher" "${APP_PUBLISHER}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "DisplayIcon" "$INSTDIR\freeton_icon.ico"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINSTALL_REG_KEY}" "EstimatedSize" $0
  WriteRegDWORD HKLM "${UNINSTALL_REG_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_REG_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetRegView 64
  SetShellVarContext all

  ; 1. Terminate running GUI process so executables can be removed cleanly.
  StrCpy $R6 "${APP_EXE}"
  StrCpy $R5 0
  Call un.WaitOrKillProcess

  ; 2. Uninstall FreetonVPNService, any active WireGuardTunnel$FreetonVPN, and %ProgramData%\FreetonVPN\tunnels.
  ${If} ${FileExists} "$INSTDIR\${SERVICE_EXE}"
    DetailPrint "Uninstalling ${BROKER_SERVICE_NAME}..."
    nsExec::ExecToStack '"$INSTDIR\${SERVICE_EXE}" --uninstall'
    Pop $0
    Pop $1
  ${Else}
    StrCpy $0 1
  ${EndIf}

  ${If} $0 != 0
    StrCpy $R8 "${BROKER_SERVICE_NAME}"
    Call un.StopServiceInR8
    Call un.DeleteServiceInR8
    StrCpy $R8 "${TUNNEL_SERVICE_NAME}"
    Call un.StopServiceInR8
    Call un.DeleteServiceInR8
  ${EndIf}

  Call un.WaitServiceProcessesStopped

  ; 3. Remove installed binaries, Start Menu shortcuts, and runtime caches/tunnels.
  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\${SERVICE_EXE}"
  Delete "$INSTDIR\tunnel.dll"
  Delete "$INSTDIR\wireguard.dll"
  Delete "$INSTDIR\freeton_icon.ico"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\Uninstall ${APP_NAME}.lnk"
  RMDir "$SMPROGRAMS\${APP_NAME}"

  ReadEnvStr $0 "ProgramData"
  ${If} $0 != ""
    RMDir /r "$0\FreetonVPN\tunnels"
    RMDir "$0\FreetonVPN"
  ${EndIf}

  RMDir /r "$LOCALAPPDATA\FreetonVPN"

  ; 4. Remove HKCU startup value (if present) and 64-bit uninstall/install registry keys.
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "FreetonVPN"
  DeleteRegKey HKLM "${UNINSTALL_REG_KEY}"
  DeleteRegKey HKLM "${APP_REG_KEY}"
SectionEnd
