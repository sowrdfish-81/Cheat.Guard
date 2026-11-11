@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

rem ============================================================
rem  Cheat.Guard Central - ONE-COMMAND BUILDER
rem  Produces exactly ONE artifact: dist\CheatGuardCentral-Setup.exe
rem  and its SHA-256 companion asset for verified auto-updates.
rem  A single Windows installer that bundles the app AND its
rem  own Java runtime - nothing else to build or download.
rem ============================================================

rem Internal MSI version only (upgrade machinery); the shipped file carries no version.
set "APP_VERSION=1.9.58"
set "APP_NAME=CheatGuardCentral"
set "SETUP_EXE=dist\CheatGuardCentral-Setup.exe"
set "CHECKSUM_FILE=%SETUP_EXE%.sha256"

echo ============================================================
echo  CheatGuard - single installer builder
echo  Output: %SETUP_EXE%
echo ============================================================
echo.

echo [1/5] Checking build tools...
where javac >nul 2>nul || (echo ERROR: javac not found. Install JDK 17+.& exit /b 1)
where jar    >nul 2>nul || (echo ERROR: jar not found. Install a full JDK.& exit /b 1)
where jpackage >nul 2>nul || (echo ERROR: jpackage not found. Install JDK 17+.& exit /b 1)

rem WiX 3.x is required by jpackage to build the .exe installer.
set "WIX_FOUND="
where candle.exe >nul 2>nul && where light.exe >nul 2>nul && set "WIX_FOUND=1"
if not defined WIX_FOUND (
  for %%D in (
    "%~dp0tools\wix"
    "%~dp0..\tools\wix"
    "%ProgramFiles(x86)%\WiX Toolset v3.14\bin"
    "%ProgramFiles(x86)%\WiX Toolset v3.11\bin"
    "%ProgramFiles%\WiX Toolset v3.14\bin"
    "%ProgramFiles%\WiX Toolset v3.11\bin"
  ) do (
    if not defined WIX_FOUND if exist "%%~D\candle.exe" if exist "%%~D\light.exe" (
      set "PATH=%%~D;!PATH!"
      set "WIX_FOUND=1"
      echo WiX found at: %%~D
    )
  )
)
if defined WIX_FOUND if not exist "%~dp0tools\wix\darice.cub" if exist "%~dp0tools\wix\bin\darice.cub" copy /y "%~dp0tools\wix\bin\darice.cub" "%~dp0tools\wix\darice.cub" >nul
if not defined WIX_FOUND (
  echo ERROR: WiX Toolset 3.x not found. jpackage needs candle.exe/light.exe to build an .exe installer.
  exit /b 1
)
echo.

echo [2/5] Cleaning previous build...
if exist bin        rmdir /s /q bin
if exist build      rmdir /s /q build
if exist dist       rmdir /s /q dist
mkdir bin
mkdir build\input
mkdir dist
echo.

echo [3/5] Compiling Java sources...
setlocal DisableDelayedExpansion
set "SRC_LIST=%TEMP%\cheatguard_sources.txt"
> "%SRC_LIST%" (
  for /r src %%F in (*.java) do @echo %%F
)
javac -encoding UTF-8 -d bin "@%SRC_LIST%"
if errorlevel 1 (echo ERROR: compilation failed.& exit /b 1)
endlocal & set "APP_VERSION=%APP_VERSION%" & set "APP_NAME=%APP_NAME%" & set "SETUP_EXE=%SETUP_EXE%"
echo Compiled OK.
echo.

echo [4/5] Packaging jar (app + resources)...
jar --create --file build\%APP_NAME%.jar --main-class com.cheatguard.Main -C bin . -C resources .
if errorlevel 1 (echo ERROR: jar packaging failed.& exit /b 1)
copy /y build\%APP_NAME%.jar build\input\%APP_NAME%.jar >nul
rem Support tools ship inside the installed app folder so an invigilator can
rem repair or diagnose a machine without the development team present.
copy /y support\emergency-restore.bat build\input\ >nul
copy /y support\diagnostics.bat build\input\ >nul
if not exist build\input\support mkdir build\input\support
copy /y support\emergency-restore.ps1 build\input\support\ >nul
copy /y support\diagnostics.ps1 build\input\support\ >nul
echo Jar OK.
echo.

echo [5/5] Building the single installer (this bundles a trimmed Java runtime)...
jpackage ^
  --type exe ^
  --input build\input ^
  --main-jar %APP_NAME%.jar ^
  --name CheatGuardCentral ^
  --app-version %APP_VERSION% ^
  --vendor "Cheat.Guard Project" ^
  --description "Cheat.Guard - exam lockdown for Windows" ^
  --icon resources\icon.ico ^
  --win-shortcut ^
  --win-menu ^
  --win-menu-group "Cheat.Guard" ^
  --win-dir-chooser ^
  --win-upgrade-uuid 8f4a2c71-3d96-4b58-ae20-6c91d7f045b3 ^
  --java-options "-Dfile.encoding=UTF-8" ^
  --java-options "-Djava.net.preferIPv4Stack=true" ^
  --add-modules java.base,java.desktop,java.management,java.logging,java.xml,jdk.crypto.ec ^
  --jlink-options "--strip-native-commands --no-header-files --no-man-pages --compress 2" ^
  --temp build\jpackage ^
  --dest dist
if errorlevel 1 (echo ERROR: jpackage failed.& exit /b 1)

echo.
move /y "dist\CheatGuardCentral-%APP_VERSION%.exe" "%SETUP_EXE%" >nul
if exist "%SETUP_EXE%" (
  echo ============================================================
  echo  BUILD SUCCESSFUL
  echo  Installer: %SETUP_EXE%
  for %%A in ("%SETUP_EXE%") do echo  Size: %%~zA bytes
  "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "$bytes=[IO.File]::ReadAllBytes('%SETUP_EXE%'); $hash=(([Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object ToString x2) -join '').ToLower(); [IO.File]::WriteAllText('%CHECKSUM_FILE%', ($hash + '  ' + [IO.Path]::GetFileName('%SETUP_EXE%') + [Environment]::NewLine), [Text.Encoding]::ASCII)"
  if errorlevel 1 (echo ERROR: checksum generation failed.& exit /b 1)
  if not exist "%CHECKSUM_FILE%" (echo ERROR: checksum asset was not produced.& exit /b 1)
  echo  Checksum: %CHECKSUM_FILE%
  echo  This ONE file contains the central monitor + Java runtime.
  echo  Double-click it to install Cheat.Guard Central.
  echo ============================================================
) else (
  echo ERROR: expected installer %SETUP_EXE% was not produced.
  exit /b 1
)
endlocal

