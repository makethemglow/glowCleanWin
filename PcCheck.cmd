@echo off
rem PcCheck: zapusk proverki. Prava administratora skript zaprosit sam.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PcCheck.ps1" %*
if errorlevel 1 pause
