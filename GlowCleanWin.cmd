@echo off
rem GlowCleanWin: zapusk proverki. Prava administratora skript zaprosit sam.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0GlowCleanWin.ps1" %*
if errorlevel 1 pause
