@echo off
cd /d "%~dp0"
echo Building ArchiveRecovery.exe (pywebview UI) from ArchiveRecovery.spec ...
pyinstaller --noconfirm ArchiveRecovery.spec
if errorlevel 1 (echo PyInstaller FAILED & exit /b 1)
echo Copying UI + hashcat engine next to the exe ...
xcopy /E /I /Y ui      "dist\ArchiveRecovery\ui"      >nul
xcopy /E /I /Y hashcat "dist\ArchiveRecovery\hashcat" >nul
echo Done. Run: dist\ArchiveRecovery\ArchiveRecovery.exe
