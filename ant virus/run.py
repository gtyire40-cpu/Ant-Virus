"""
Punto de entrada de la aplicación
"""

import sys

# Intenta usar GUI (requiere tkinter), si falla usa CLI
try:
    from src.main import main
    main()
except ImportError:
    # Fallback a CLI si tkinter no está disponible
    from src.cli import main
    main()
