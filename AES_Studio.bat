@echo off
rem AES Studio - zapusk na Windows (podviinyi klik abo z komandnoho riadka).
rem Bez parametriv vidkryvaie prohramu; z parametramy peredaie yikh u run.py,
rem napryklad:  AES_Studio.bat selftest
chcp 65001 >nul
setlocal
set "PYTHONUTF8=1"
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo Python 3.10+ не знайдено. Встановіть його з https://www.python.org/downloads/
    echo і позначте пункт "Add python.exe to PATH".
    pause
    exit /b 1
)

%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 (
    echo Потрібен Python 3.10 або новіший.
    %PY% --version
    pause
    exit /b 1
)

if not "%~1"=="" goto args

%PY% -c "import tkinter" 2>nul
if errorlevel 1 (
    echo У цьому Python немає модуля tkinter. Перевстановіть Python з python.org
    echo з увімкненим компонентом "tcl/tk and IDLE".
    pause
    exit /b 1
)
echo Запуск AES Studio...
%PY% run.py gui
if errorlevel 1 pause
exit /b %errorlevel%

:args
%PY% run.py %*
exit /b %errorlevel%
