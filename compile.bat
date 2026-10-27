@echo off
REM =========================================================================
REM PhishGuard — Windows Compilation Script
REM Compiles Java source files and tests into bin/
REM =========================================================================

echo [PhishGuard] Checking Java Development Kit (JDK)...
where javac >nul 2>nul
if %errorlevel% neq 0 (
    if exist "C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot\bin\javac.exe" (
        set "PATH=C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot\bin;%PATH%"
    )
)
where javac >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] 'javac' compiler was not found in your system PATH!
    echo Please install Java 17+ or configure your JAVA_HOME and PATH.
    echo Refer to docs\BEGINNER_SETUP.md for simple step-by-step instructions.
    pause
    exit /b 1
)

echo [PhishGuard] Creating bin/ build directory...
if not exist "bin" mkdir "bin"

echo [PhishGuard] Compiling application source code...
javac -encoding UTF-8 -d bin src\com\phishguard\model\*.java src\com\phishguard\analyzer\*.java src\com\phishguard\history\*.java src\com\phishguard\util\*.java src\com\phishguard\ui\*.java src\com\phishguard\Main.java
if %errorlevel% neq 0 (
    echo [ERROR] Compilation of main source files failed!
    pause
    exit /b 1
)

echo [PhishGuard] Compiling test suite...
javac -encoding UTF-8 -cp bin -d bin test\com\phishguard\PhishGuardTestRunner.java
if %errorlevel% neq 0 (
    echo [ERROR] Compilation of test runner failed!
    pause
    exit /b 1
)

echo.
echo =====================================================
echo  [SUCCESS] PhishGuard build completed successfully!
echo =====================================================
echo You can now run:
echo   - run.bat   : To launch the GUI application
echo   - test.bat  : To execute the automated test runner
echo =====================================================
