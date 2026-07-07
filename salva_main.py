"""Punto d'ingresso a file singolo per PyInstaller (e per l'esecuzione diretta).

    python3 salva_main.py check

PyInstaller lo usa come script da congelare in un binario nativo:
    pyinstaller --onefile --name salva --paths . salva_main.py
"""
from salva.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
