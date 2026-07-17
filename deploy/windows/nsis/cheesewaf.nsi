; CheeseWAF Windows NSIS installer
; --------------------------------
; Scope (implementation_plan):
;   - copy binaries + config template
;   - optional Windows Service registration hooks
;   - start menu + uninstaller
;   - NEVER ship API keys, private keys, or default weak passwords
;
; Build (on a machine with NSIS + built binaries):
;   makensis /DVERSION=0.1.0 /DSOURCE_DIR=..\..\..\dist\windows-payload cheesewaf.nsi
;
; SOURCE_DIR is expected to contain:
;   cheesewaf.exe
;   cheesewaf-gui.exe   (optional but recommended)
;   waf-cli.exe         (optional; copy of cheesewaf.exe is fine)
;   configs\cheesewaf.yaml  (template WITHOUT secrets)

!ifndef VERSION
  !define VERSION "0.0.0-dev"
!endif
!ifndef SOURCE_DIR
  !define SOURCE_DIR "..\..\..\bin"
!endif
!ifndef PRODUCT_NAME
  !define PRODUCT_NAME "CheeseWAF"
!endif

Name "${PRODUCT_NAME} ${VERSION}"
OutFile "..\..\..\dist\CheeseWAF-${VERSION}-setup.exe"
InstallDir "$PROGRAMFILES64\CheeseWAF"
RequestExecutionLevel admin
Unicode true
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "SimpChinese"

Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Section "Install"
  SetOutPath "$INSTDIR"

  ; Core binaries (fail soft if a component is missing from SOURCE_DIR)
  File /nonfatal "${SOURCE_DIR}\cheesewaf.exe"
  File /nonfatal "${SOURCE_DIR}\cheesewaf-gui.exe"
  File /nonfatal "${SOURCE_DIR}\waf-cli.exe"

  ; Config template only — never secrets / private keys
  CreateDirectory "$INSTDIR\configs"
  File /nonfatal "/oname=configs\cheesewaf.yaml" "${SOURCE_DIR}\configs\cheesewaf.yaml"
  File /nonfatal "/oname=configs\cheesewaf.yaml" "${SOURCE_DIR}\cheesewaf.yaml"

  CreateDirectory "$INSTDIR\data"
  CreateDirectory "$INSTDIR\logs"
  CreateDirectory "$INSTDIR\data\logs"
  CreateDirectory "$INSTDIR\data\run"

  ; Uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Start menu — pass absolute config/data-dir so CWD is irrelevant
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\CheeseWAF Controller.lnk" \
    "$INSTDIR\cheesewaf-gui.exe" \
    '--config "$INSTDIR\configs\cheesewaf.yaml" --data-dir "$INSTDIR\data"' \
    "$INSTDIR\cheesewaf-gui.exe" 0
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\CLI Shell.lnk" \
    "$SYSDIR\cmd.exe" \
    '/K "cd /d "$INSTDIR" && echo CheeseWAF CLI — run cheesewaf.exe --help"'
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

  ; Desktop controller shortcut (optional convenience)
  CreateShortCut "$DESKTOP\CheeseWAF Controller.lnk" \
    "$INSTDIR\cheesewaf-gui.exe" \
    '--config "$INSTDIR\configs\cheesewaf.yaml" --data-dir "$INSTDIR\data"'

  ; Optional service registration (best-effort).
  ; Users may still run zip/bin style without a service.
  ; Quoted binPath is required when paths contain spaces (Program Files).
  nsExec::ExecToLog 'sc.exe create CheeseWAF binPath= "\"$INSTDIR\cheesewaf.exe\" serve --config \"$INSTDIR\configs\cheesewaf.yaml\" --data-dir \"$INSTDIR\data\"" start= demand DisplayName= "CheeseWAF"'
  nsExec::ExecToLog 'sc.exe description CheeseWAF "CheeseWAF Web Application Firewall"'

  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "Publisher" "CheeseCloud"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "InstallLocation" "$INSTDIR"
SectionEnd

Section "Uninstall"
  nsExec::ExecToLog 'sc.exe stop CheeseWAF'
  nsExec::ExecToLog 'sc.exe delete CheeseWAF'

  Delete "$INSTDIR\cheesewaf.exe"
  Delete "$INSTDIR\cheesewaf-gui.exe"
  Delete "$INSTDIR\waf-cli.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir /r "$INSTDIR\configs"
  ; Preserve user data/logs by default (explicit product choice)
  ; RMDir /r "$INSTDIR\data"
  ; RMDir /r "$INSTDIR\logs"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\${PRODUCT_NAME}\CheeseWAF Controller.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\CLI Shell.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
  Delete "$DESKTOP\CheeseWAF Controller.lnk"

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
SectionEnd
