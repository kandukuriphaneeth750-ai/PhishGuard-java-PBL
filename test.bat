@echo off
REM =========================================================================
REM PhishGuard — Windows Test Runner Script
REM Executes the Automated Test Suite and Outputs Results
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
    pause
    exit /b 1
)

if not exist "bin\com\phishguard\PhishGuardTestRunner.class" (
    echo [PhishGuard] Test runner is not yet compiled. Running compile.bat first...
    call compile.bat
    if %errorlevel% neq 0 exit /b 1
)

echo [PhishGuard] Running 13 Automated Test Suites...
java -cp bin com.phishguard.PhishGuardTestRunner
pause
