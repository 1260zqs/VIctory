@echo off
setlocal
cd /d "%~dp0"

if /i "%~1"=="diag" (
    echo Building VIctory with diagnostics...
    cargo build --profile diag -p victory --features diagnostics
    set "OUTPUT=target\diag\victory.exe"
) else (
    echo Building VIctory release...
    cargo build --release -p victory
    set "OUTPUT=target\release\victory.exe"
)

if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

echo.
echo Build successful!
echo Output: %OUTPUT%
:: target\release\victory.exe run "game_scarlett_master.xex" --execute --debugger  --break 0x145A91BD0