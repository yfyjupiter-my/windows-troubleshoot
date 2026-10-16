@echo off
rem Build dist\AppTriage.exe (must be run on Windows; PyInstaller cannot cross-compile).
setlocal
cd /d "%~dp0"

uv sync --group dev || exit /b 1
uv run pyinstaller --onefile --windowed --uac-admin --name AppTriage --paths . --collect-submodules app_triage app_triage\__main__.py || exit /b 1

echo.
echo Done: dist\AppTriage.exe
endlocal
