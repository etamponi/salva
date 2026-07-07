#!/usr/bin/env python3
"""Costruisce il file singolo condivisibile: dist/salva.pyz

Uno zipapp Python: UN solo file che gira su Linux, macOS e Windows a patto che
sul computer di destinazione ci sia Python 3.

    python3 build.py

Poi condividi 'dist/salva.pyz'. Chi lo riceve lo esegue con:
    ./salva.pyz            (Linux/macOS, dopo 'chmod +x salva.pyz')
    python3 salva.pyz      (ovunque)
    py salva.pyz           (Windows)

Non servono dipendenze esterne: usa solo la libreria standard (modulo zipapp).
"""
from __future__ import annotations

import os
import shutil
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PKG = ROOT / "salva"
DIST = ROOT / "dist"


def main() -> int:
    if not PKG.is_dir():
        print("errore: cartella 'salva/' non trovata accanto a build.py")
        return 1

    DIST.mkdir(exist_ok=True)
    target = DIST / "salva.pyz"

    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / "app"
        stage.mkdir()
        # copia il pacchetto escludendo i bytecode
        shutil.copytree(
            PKG,
            stage / "salva",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        # __main__.py scritto a mano: quello autogenerato da zipapp (main=...)
        # chiama main() SENZA propagarne il valore di ritorno, perdendo il
        # codice di uscita. Qui lo propaghiamo con SystemExit.
        (stage / "__main__.py").write_text(
            "import sys\n"
            "from salva.cli import main\n"
            "sys.exit(main())\n"
        )
        zipapp.create_archive(
            stage,
            target=str(target),
            interpreter="/usr/bin/env python3",
            compressed=True,
        )

    os.chmod(target, 0o755)
    size_kb = target.stat().st_size / 1024
    print(f"creato {target}  ({size_kb:.1f} KiB)")
    print("condividi questo file; per eseguirlo:  python3 salva.pyz")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
