@echo off
cd /d %~dp0
cargo build --release
if errorlevel 1 exit /b 1
copy /Y target\release\rva_to_symbol.exe ..\rva_to_symbol.exe
if errorlevel 1 exit /b 1
