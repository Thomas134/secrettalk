@echo off
chcp 65001 >nul
cd /d "%~dp0"
title SecretTalk - one-click public share
echo.
echo  Starting public link...
echo  First run downloads cloudflared (~53 MB), then it is instant.
echo  When ready, copy the https://xxxx.trycloudflare.com address.
echo  Close this window (or Ctrl+C) to go offline.
echo.
call npm run share
echo.
echo Service stopped. Press any key to close.
pause >nul
