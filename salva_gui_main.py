"""Punto d'ingresso a file singolo della GUI, per PyInstaller.

    pyinstaller --onefile --name salva-gui --paths . salva_gui_main.py
"""
from salva.gui import main

if __name__ == "__main__":
    raise SystemExit(main())
