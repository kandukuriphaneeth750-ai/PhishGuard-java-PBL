@echo off
REM =========================================================================
REM PhishGuard — Windows Launch Script
REM Runs the PhishGuard GUI Dashboard
REM =========================================================================

where java >nul 2>nul
if %errorlevel% neq 0 (
    if exist "C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot\bin\java.exe" (
        set "PATH=C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot\bin;%PATH%"
    )
)
where java >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] 'java' runtime was not found in your system PATH!
    echo Please install Java 17+ or configure your JAVA_HOME and PATH.
    echo Refer to docs\BEGINNER_SETUP.md for simple instructions.
    pause
    exit /b 1
)

if not exist "bin\com\phishguard\Main.class" (
    echo [PhishGuard] Application is not yet compiled. Running compile.bat first...
    call compile.bat
    if %errorlevel% neq 0 exit /b 1
)

echo [PhishGuard] Launching Desktop Dashboard...
java -cp bin com.phishguard.Main
