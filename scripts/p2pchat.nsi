; p2pchat Windows NSIS installer script
; Build: makensis p2pchat.nsi

!define PRODUCT_NAME "P2P Chat"
!define PRODUCT_VERSION "0.1.0"
!define PRODUCT_PUBLISHER "p2p-chat"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "p2pchat-setup-${PRODUCT_VERSION}.exe"
InstallDir "$PROGRAMFILES64\${PRODUCT_NAME}"
RequestExecutionLevel admin

Section "Install" SecMain
  SetOutPath "$INSTDIR"

  ; Main executable (paths relative to repo root when using -NOCD)
  File "target/x86_64-pc-windows-gnu/release/p2pchat.exe"

  ; MinGW runtime DLLs
  File /nonfatal "target/x86_64-pc-windows-gnu/release/libgcc_s_seh-1.dll"
  File /nonfatal "target/x86_64-pc-windows-gnu/release/libstdc++-6.dll"
  File /nonfatal "target/x86_64-pc-windows-gnu/release/libwinpthread-1.dll"

  ; Create Start Menu shortcut
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\p2pchat.exe"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe"

  ; Create uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Register in Add/Remove Programs
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
                   "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
                   "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
                   "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
                   "DisplayVersion" "${PRODUCT_VERSION}"
SectionEnd

Section "Uninstall"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
  RmDir "$SMPROGRAMS\${PRODUCT_NAME}"
  Delete "$INSTDIR\p2pchat.exe"
  Delete "$INSTDIR\uninstall.exe"
  RmDir "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
SectionEnd
