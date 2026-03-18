!include "MUI2.nsh"

Name "AegisAI360 Endpoint Agent"
OutFile "AegisAI360-Agent-Setup.exe"
InstallDir "$PROGRAMFILES\AegisAI360\Agent"
RequestExecutionLevel admin
Unicode True

!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "AegisAI360-Header.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "AegisAI360-Banner.bmp"

Var DEVICE_TOKEN

!insertmacro MUI_PAGE_WELCOME
Page custom TokenPageCreate TokenPageLeave
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Function TokenPageCreate
  !insertmacro MUI_HEADER_TEXT "Device Token" "Enter your AegisAI360 device token"
  nsDialogs::Create 1018
  Pop $0

  ${NSD_CreateLabel} 0 0 100% 36u "Enter the device token generated from your AegisAI360 dashboard.$\n$\nGo to: Dashboard > Endpoints > Generate Device Token"
  Pop $0

  ${NSD_CreateLabel} 0 46u 100% 12u "Device Token:"
  Pop $0

  ${NSD_CreateText} 0 60u 100% 14u ""
  Pop $1

  nsDialogs::Show
FunctionEnd

Function TokenPageLeave
  ${NSD_GetText} $1 $DEVICE_TOKEN
  StrCmp $DEVICE_TOKEN "" 0 +3
    MessageBox MB_ICONEXCLAMATION "Please enter a device token. You can generate one from the AegisAI360 dashboard."
    Abort
FunctionEnd

Section "Install"
  SetOutPath "$INSTDIR"

  File "agent.exe"
  File "AegisAI360Agent.exe"
  File "AegisAI360Agent.xml"
  File "config.json"

  CreateDirectory "$INSTDIR\logs"

  FileOpen $0 "$INSTDIR\config.json" w
  FileWrite $0 '{$\n'
  FileWrite $0 '  "serverUrl": "https://aegisai360.com",$\n'
  FileWrite $0 '  "apiKey": "$DEVICE_TOKEN",$\n'
  FileWrite $0 '  "agentVersion": "8.2.1",$\n'
  FileWrite $0 '  "heartbeatInterval": 30,$\n'
  FileWrite $0 '  "commandPollInterval": 5,$\n'
  FileWrite $0 '  "logMaxSizeMB": 10,$\n'
  FileWrite $0 '  "logMaxBackups": 5$\n'
  FileWrite $0 '}$\n'
  FileClose $0

  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent" \
    "DisplayName" "AegisAI360 Endpoint Agent"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent" \
    "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent" \
    "Publisher" "FAHADERA LLC"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent" \
    "DisplayVersion" "8.2.1"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent" \
    "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent" \
    "NoRepair" 1

  CreateDirectory "$SMPROGRAMS\AegisAI360"
  CreateShortcut "$SMPROGRAMS\AegisAI360\AegisAI360 Agent.lnk" "$INSTDIR\agent.exe" "--tray" \
    "$INSTDIR\agent.exe" 0 SW_SHOWMINIMIZED "" "AegisAI360 Endpoint Agent"
  CreateShortcut "$SMPROGRAMS\AegisAI360\Uninstall Agent.lnk" "$INSTDIR\uninstall.exe"
  CreateShortcut "$DESKTOP\AegisAI360 Agent.lnk" "$INSTDIR\agent.exe" "--tray" \
    "$INSTDIR\agent.exe" 0 SW_SHOWMINIMIZED "" "AegisAI360 Endpoint Agent"

  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "AegisAI360Agent" \
    '"$INSTDIR\agent.exe" --tray'

  DetailPrint "Installing AegisAI360 Agent service..."
  nsExec::ExecToLog '"$INSTDIR\AegisAI360Agent.exe" install'

  DetailPrint "Starting AegisAI360 Agent service..."
  nsExec::ExecToLog '"$INSTDIR\AegisAI360Agent.exe" start'

  DetailPrint "Launching system tray agent..."
  Exec '"$INSTDIR\agent.exe" --tray'

  DetailPrint "Installation complete."
SectionEnd

Section "Uninstall"
  DetailPrint "Stopping AegisAI360 Agent service..."
  nsExec::ExecToLog '"$INSTDIR\AegisAI360Agent.exe" stop'

  DetailPrint "Uninstalling AegisAI360 Agent service..."
  nsExec::ExecToLog '"$INSTDIR\AegisAI360Agent.exe" uninstall'

  Sleep 2000

  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "AegisAI360Agent"

  Delete "$INSTDIR\agent.exe"
  Delete "$INSTDIR\AegisAI360Agent.exe"
  Delete "$INSTDIR\AegisAI360Agent.xml"
  Delete "$INSTDIR\config.json"
  Delete "$INSTDIR\uninstall.exe"
  RMDir /r "$INSTDIR\logs"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\AegisAI360\AegisAI360 Agent.lnk"
  Delete "$SMPROGRAMS\AegisAI360\Uninstall Agent.lnk"
  RMDir "$SMPROGRAMS\AegisAI360"
  Delete "$DESKTOP\AegisAI360 Agent.lnk"

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent"
SectionEnd
