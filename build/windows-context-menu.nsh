!macro RegisterAvikalContextMenu ROOT_KEY KEY_NAME MENU_LABEL ACTION_NAME
  WriteRegStr ${ROOT_KEY} "Software\Classes\AllFilesystemObjects\shell\${KEY_NAME}" "" "${MENU_LABEL}"
  WriteRegStr ${ROOT_KEY} "Software\Classes\AllFilesystemObjects\shell\${KEY_NAME}" "Icon" "$INSTDIR\RookDuel Avikal.exe"
  WriteRegStr ${ROOT_KEY} "Software\Classes\AllFilesystemObjects\shell\${KEY_NAME}" "MultiSelectModel" "Player"
  WriteRegStr ${ROOT_KEY} "Software\Classes\AllFilesystemObjects\shell\${KEY_NAME}\command" "" '$\"$INSTDIR\RookDuel Avikal.exe$\" --shell-action=${ACTION_NAME} %V'
!macroend

!macro UnregisterAvikalContextMenu ROOT_KEY KEY_NAME
  DeleteRegKey ${ROOT_KEY} "Software\Classes\AllFilesystemObjects\shell\${KEY_NAME}"
!macroend

!macro customInstall
  !insertmacro RegisterAvikalContextMenu HKCU "RookDuelAvikal.Encrypt" "Encrypt & Compress to .avk" "encrypt"
  !insertmacro RegisterAvikalContextMenu HKCU "RookDuelAvikal.TimeCapsule" "TimeLock it" "timecapsule"
!macroend

!macro customUnInstall
  !insertmacro UnregisterAvikalContextMenu HKCU "RookDuelAvikal.Encrypt"
  !insertmacro UnregisterAvikalContextMenu HKCU "RookDuelAvikal.TimeCapsule"
!macroend
