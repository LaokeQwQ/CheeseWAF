; CheeseWAF Windows NSIS installer skeleton
; -----------------------------------------
; Scope (implementation_plan):
;   - copy binaries + config template
;   - optional Windows Service registration hooks
;   - start menu + uninstaller
;   - NEVER ship API keys, private keys, or default weak passwords
;
; Build (on a machine with NSIS + built binaries):
;   makensis /DVERSION=0.1.0 /DSOURCE_DIR=..\..\..\dist\windows-amd64 cheesewaf.nsi
;
; SOURCE_DIR is expected to contain:
;   cheesewaf.exe
;   cheesewaf-gui.exe   (optional but recommended)
;   configs\cheesewaf.yaml  (template without secrets)

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

Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Section "Install"
  SetOutPath "$INSTDIR"

  ; Core binaries
  File /nonfatal "${SOURCE_DIR}\cheesewaf.exe"
  File /nonfatal "${SOURCE_DIR}\cheesewaf-gui.exe"
  File /nonfatal "${SOURCE_DIR}\waf-cli.exe"

  ; Config template only — never secrets
  CreateDirectory "$INSTDIR\configs"
  File /nonfatal "/oname=configs\cheesewaf.yaml" "${SOURCE_DIR}\configs\cheesewaf.yaml"
  File /nonfatal "/oname=configs\cheesewaf.yaml" "${SOURCE_DIR}\cheesewaf.yaml"

  CreateDirectory "$INSTDIR\data"
  CreateDirectory "$INSTDIR\logs"

  ; Uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Start menu
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\CheeseWAF Controller.lnk" "$INSTDIR\cheesewaf-gui.exe"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

  ; Optional service registration (best-effort; fails soft if sc.exe unavailable)
  ; Users may still run zip/bin style without a service.
  nsExec::ExecToLog 'sc.exe create CheeseWAF binPath= "\"$INSTDIR\cheesewaf.exe\" serve --config \"$INSTDIR\configs\cheesewaf.yaml\" --data-dir \"$INSTDIR\data\"" start= demand DisplayName= "CheeseWAF"'
  nsExec::ExecToLog 'sc.exe description CheeseWAF "CheeseWAF Web Application Firewall"'

  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "Publisher" "CheeseCloud"
SectionEnd

Section "Uninstall"
  nsExec::ExecToLog 'sc.exe stop CheeseWAF'
  nsExec::ExecToLog 'sc.exe delete CheeseWAF'

  Delete "$INSTDIR\cheesewaf.exe"
  Delete "$INSTDIR\cheesewaf-gui.exe"
  Delete "$INSTDIR\waf-cli.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir /r "$INSTDIR\configs"
  ; Preserve user data by default
  ; RMDir /r "$INSTDIR\data"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\${PRODUCT_NAME}\CheeseWAF Controller.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
SectionEnd
