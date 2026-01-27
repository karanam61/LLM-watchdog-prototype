@echo off
set ROOT=%~dp0..\..
for %%I in ("%ROOT%") do set ROOT=%%~fI

py -c "import sys; print(sys.executable)" > "%ROOT%\python_path.txt"
