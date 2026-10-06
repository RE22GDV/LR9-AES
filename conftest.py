"""Додає ``src/`` у шлях пошуку модулів, щоб pytest працював без встановлення."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
