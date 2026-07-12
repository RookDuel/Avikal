!ifndef OUTPUT_FILE
  !error "OUTPUT_FILE is required"
!endif
!ifndef PAYLOAD_ROOT
  !error "PAYLOAD_ROOT is required"
!endif
!ifndef APP_VERSION
  !define APP_VERSION "0.0.0"
!endif

Unicode true
RequestExecutionLevel user
Name "RookDuel-Avikal CLI"
OutFile "${OUTPUT_FILE}"
InstallDir "$LOCALAPPDATA\Programs\RookDuel-Avikal-CLI"
BrandingText "RookDuel-Avikal CLI"
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "LogicLib.nsh"

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR\backend"
  File /r "${PAYLOAD_ROOT}\backend\*.*"

  SetOutPath "$INSTDIR\backend-runtime"
  File /r "${PAYLOAD_ROOT}\backend-runtime\*.*"

  SetOutPath "$INSTDIR"
  FileOpen $0 "$INSTDIR\avikal.cmd" w
  FileWrite $0 '@echo off$\r$\n'
  FileWrite $0 '$\"$INSTDIR\backend\avikal-backend.exe$\" %*$\r$\n'
  FileClose $0

  IfFileExists "$INSTDIR\backend\avikal-backend.exe" backend_exists
    SetErrorLevel 91
    Abort
  backend_exists:

  IfFileExists "$INSTDIR\backend-runtime\pqc\bin\openssl.exe" openssl_exists
    SetErrorLevel 92
    Abort
  openssl_exists:

  ExecWait '"$INSTDIR\backend\avikal-backend.exe" --verify-runtime' $0
  ${If} $0 != 0
    SetErrorLevel 100
    Abort
  ${EndIf}

  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "DisplayName" "RookDuel-Avikal CLI"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "Publisher" "RookDuel"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "DisplayIcon" "$INSTDIR\backend\avikal-backend.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI" "NoRepair" 1
SectionEnd

Section "Uninstall"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RookDuel-Avikal CLI"
  RMDir /r "$INSTDIR"
SectionEnd
