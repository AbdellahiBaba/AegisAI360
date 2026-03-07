!include "MUI2.nsh"

Name "AegisAI360 Endpoint Agent"
OutFile "AegisAI360-Agent-Setup.exe"
InstallDir "$PROGRAMFILES\AegisAI360\Agent"
RequestExecutionLevel admin
Unicode True

!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"

  File "agent.exe"
  File "AegisAI360Agent.exe"
  File "AegisAI360Agent.xml"

  CreateDirectory "$INSTDIR\logs"

  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent" \
    "DisplayName" "AegisAI360 Endpoint Agent"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent" \
    "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent" \
    "Publisher" "AegisAI360"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent" \
    "DisplayVersion" "1.0.0"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent" \
    "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent" \
    "NoRepair" 1

  DetailPrint "Installing AegisAI360 Agent service..."
  nsExec::ExecToLog '"$INSTDIR\AegisAI360Agent.exe" install'

  DetailPrint "Starting AegisAI360 Agent service..."
  nsExec::ExecToLog '"$INSTDIR\AegisAI360Agent.exe" start'

  DetailPrint "Installation complete."
SectionEnd

Section "Uninstall"
  DetailPrint "Stopping AegisAI360 Agent service..."
  nsExec::ExecToLog '"$INSTDIR\AegisAI360Agent.exe" stop'

  DetailPrint "Uninstalling AegisAI360 Agent service..."
  nsExec::ExecToLog '"$INSTDIR\AegisAI360Agent.exe" uninstall'

  Sleep 2000

  Delete "$INSTDIR\agent.exe"
  Delete "$INSTDIR\AegisAI360Agent.exe"
  Delete "$INSTDIR\AegisAI360Agent.xml"
  Delete "$INSTDIR\uninstall.exe"
  RMDir /r "$INSTDIR\logs"
  RMDir "$INSTDIR"

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent"
SectionEnd
