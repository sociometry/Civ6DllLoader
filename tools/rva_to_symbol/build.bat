@echo off
rem ============================================================================
rem build_rva_to_symbol.bat - regenerate symbol tables and package the tool
rem
rem Steps:
rem   1) python tools\gen_rva_map.py   build compressed tables from the three
rem      symdb JSONs. The data is embedded at COMPILE TIME via include_bytes!,
rem      so the JSON changed means this step must be re-run before building.
rem   2) cargo build --release         compile the Rust tool
rem   3) copy the artifact to tools\rva_to_symbol.exe
rem
rem Arguments:
rem   %*  passed straight through to gen_rva_map.py (e.g. --check to verify
rem       without writing, or --image dx12 to rebuild one image). Passing any
rem       argument SKIPS the compile+copy step, for check-only usage.
rem
rem Note: comments are ASCII on purpose. A .bat mixing UTF-8 text with a GBK
rem console gets its lines mis-parsed (cmd reads them as commands).
rem ============================================================================
setlocal
cd /d "%~dp0"

set REPO=%~dp0..\..
set GEN=%REPO%\tools\gen_rva_map.py

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] python not found on PATH
    exit /b 1
)

where cargo >nul 2>nul
if errorlevel 1 (
    echo [ERROR] cargo not found, install the Rust toolchain first
    exit /b 1
)

echo == [1/3] generate symbol tables
if "%~1"=="" (
    python "%GEN%"
) else (
    python "%GEN%" %*
)
if errorlevel 1 (
    echo [ERROR] gen_rva_map.py failed
    exit /b 1
)

rem check-only / single-image rebuild: do not compile and copy
if not "%~1"=="" (
    echo.
    echo == argument given, skipping compile and copy
    exit /b 0
)

echo.
echo == [2/3] build rva_to_symbol
cargo build --release
if errorlevel 1 (
    echo [ERROR] cargo build failed
    exit /b 1
)

echo.
echo == [3/3] install to tools\rva_to_symbol.exe
copy /Y "target\release\rva_to_symbol.exe" "..\rva_to_symbol.exe" >nul
if errorlevel 1 (
    echo [ERROR] copy failed ^(target may be in use^)
    exit /b 1
)

for %%F in ("..\rva_to_symbol.exe") do echo     %%~fF  %%~zF bytes
echo.
echo Done. Examples:
echo     rva_to_symbol -gamecore 0x8A09C
echo     rva_to_symbol -dx12 0x8A09C
echo     rva_to_symbol --list
endlocal
