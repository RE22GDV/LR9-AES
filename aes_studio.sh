#!/usr/bin/env bash
# AES Studio — запуск на Linux і macOS.
# Без параметрів відкриває програму; з параметрами передає їх у run.py,
# наприклад:  ./aes_studio.sh selftest
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONIOENCODING=utf-8

PY=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
        PY="$candidate"
        break
    fi
done
if [ -z "$PY" ]; then
    echo "Потрібен Python 3.10 або новіший."
    echo "  Ubuntu/Debian: sudo apt install python3"
    echo "  macOS:         brew install python  (або інсталятор з python.org)"
    exit 1
fi

if [ "$#" -eq 0 ]; then
    if ! "$PY" -c 'import tkinter' 2>/dev/null; then
        echo "У цьому Python немає модуля tkinter (графічний інтерфейс)."
        echo "  Ubuntu/Debian: sudo apt install python3-tk"
        echo "  Fedora:        sudo dnf install python3-tkinter"
        echo "  macOS (brew):  brew install python-tk"
        exit 1
    fi
    exec "$PY" run.py gui
fi

exec "$PY" run.py "$@"
