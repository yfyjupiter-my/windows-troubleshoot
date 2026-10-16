"""``python -m app_triage`` and the PyInstaller entry script (hence the absolute import)."""
import sys

from app_triage.main import main

if __name__ == "__main__":
    sys.exit(main())
