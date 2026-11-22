@echo off
REM Build CipherLab 32. Run inside the "x86 Native Tools Command Prompt for VS 2022"
REM (or let the VS Code task do it). Set IRVINE to the folder containing Irvine32.inc / Irvine32.lib
if "%IRVINE%"=="" set IRVINE=C:\Irvine
ml /c /coff /nologo /I "%IRVINE%" CipherLab.asm
if errorlevel 1 goto end
link /nologo /subsystem:console /INCREMENTAL:NO /libpath:"%IRVINE%" CipherLab.obj Irvine32.lib kernel32.lib user32.lib
if errorlevel 1 goto end
echo.
echo Build OK - now run CipherLab.exe
:end
