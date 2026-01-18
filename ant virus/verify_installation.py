#!/usr/bin/env python3
"""
Script de verificación final del escáner de antivirus v1.0
Ejecutar: python verify_installation.py
"""

import os
import sys
import hashlib
from pathlib import Path

def print_header(text):
    print(f"\n{'═'*70}")
    print(f"  {text}")
    print(f"{'═'*70}\n")

def print_check(status, text):
    symbol = "✓" if status else "✗"
    color_start = "\033[92m" if status else "\033[91m"
    color_end = "\033[0m"
    print(f"  {color_start}{symbol}{color_end} {text}")

print_header("VERIFICACIÓN DE INSTALACIÓN - ESCÁNER DE ANTIVIRUS v1.0")

# 1. Verificar estructura de directorios
print("1️⃣  ESTRUCTURA DE DIRECTORIOS")
print("-" * 70)

dirs_check = {
    "src": os.path.isdir("src"),
    "quarantine": os.path.isdir("quarantine"),
    ".venv": os.path.isdir(".venv")
}

for dir_name, exists in dirs_check.items():
    print_check(exists, f"Directorio '{dir_name}': {'OK' if exists else 'NO ENCONTRADO'}")

# 2. Verificar archivos principales
print("\n2️⃣  ARCHIVOS PRINCIPALES")
print("-" * 70)

files_check = {
    "antivirus.py": os.path.isfile("antivirus.py"),
    "src/scanner.py": os.path.isfile("src/scanner.py"),
    "src/database.py": os.path.isfile("src/database.py"),
    "src/utils.py": os.path.isfile("src/utils.py"),
    "src/watcher.py": os.path.isfile("src/watcher.py"),
    "src/virustotal.py": os.path.isfile("src/virustotal.py"),
    "src/cli.py": os.path.isfile("src/cli.py"),
    "generate_report.py": os.path.isfile("generate_report.py")
}

for file_name, exists in files_check.items():
    print_check(exists, f"Archivo '{file_name}': {'OK' if exists else 'NO ENCONTRADO'}")

# 3. Verificar documentación
print("\n3️⃣  DOCUMENTACIÓN")
print("-" * 70)

docs_check = {
    "README.md": os.path.isfile("README.md"),
    "CARACTERISTICAS_COMPLETAS.md": os.path.isfile("CARACTERISTICAS_COMPLETAS.md"),
    "QUICK_START.md": os.path.isfile("QUICK_START.md"),
    "RESUMEN_FINAL.md": os.path.isfile("RESUMEN_FINAL.md"),
    "MEJORAS_IMPLEMENTADAS.md": os.path.isfile("MEJORAS_IMPLEMENTADAS.md")
}

for doc_name, exists in docs_check.items():
    print_check(exists, f"Doc '{doc_name}': {'OK' if exists else 'NO ENCONTRADO'}")

# 4. Verificar módulos Python
print("\n4️⃣  MÓDULOS PYTHON")
print("-" * 70)

try:
    from src.scanner import AntivirusScanner
    print_check(True, "AntivirusScanner: Importable")
except:
    print_check(False, "AntivirusScanner: Error al importar")

try:
    from src.database import MalwareDatabase, ScanHistory, SignatureUpdater
    print_check(True, "Database (MalwareDatabase, ScanHistory, SignatureUpdater): Importable")
except:
    print_check(False, "Database: Error al importar")

try:
    from src.utils import FileAnalyzer, ArchiveAnalyzer
    print_check(True, "Utils (FileAnalyzer, ArchiveAnalyzer): Importable")
except:
    print_check(False, "Utils: Error al importar")

try:
    from src.watcher import FileWatcher, ScheduledScanner
    print_check(True, "Watcher (FileWatcher, ScheduledScanner): Importable")
except:
    print_check(False, "Watcher: Error al importar")

try:
    from src.virustotal import VirusTotalScanner
    print_check(True, "VirusTotal: Importable")
except:
    print_check(False, "VirusTotal: Error al importar")

# 5. Verificar dependencias
print("\n5️⃣  DEPENDENCIAS EXTERNAS")
print("-" * 70)

deps_check = {
    "requests": True,
    "zipfile": True,
    "sqlite3": True,
    "hashlib": True
}

for dep_name in deps_check.keys():
    try:
        __import__(dep_name)
        print_check(True, f"Módulo '{dep_name}': OK")
    except ImportError:
        print_check(False, f"Módulo '{dep_name}': NO DISPONIBLE")

# 6. Estadísticas de código
print("\n6️⃣  ESTADÍSTICAS DE CÓDIGO")
print("-" * 70)

def count_lines(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return len(f.readlines())
    except:
        return 0

stats = {
    "antivirus.py": count_lines("antivirus.py"),
    "src/scanner.py": count_lines("src/scanner.py"),
    "src/database.py": count_lines("src/database.py"),
    "src/utils.py": count_lines("src/utils.py"),
    "src/watcher.py": count_lines("src/watcher.py"),
    "src/virustotal.py": count_lines("src/virustotal.py"),
    "src/cli.py": count_lines("src/cli.py"),
    "generate_report.py": count_lines("generate_report.py")
}

total_lines = sum(stats.values())

for file_name, lines in stats.items():
    print(f"  {file_name}: {lines} líneas")

print(f"\n  TOTAL: {total_lines} líneas de código\n")

# 7. Verificar base de datos
print("\n7️⃣  BASE DE DATOS SQLITE")
print("-" * 70)

db_exists = os.path.isfile("scan_history.db")
print_check(db_exists, f"scan_history.db: {'Existe' if db_exists else 'No existe (se creará al primer escaneo)'}")

if db_exists:
    try:
        import sqlite3
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        table_names = [t[0] for t in tables]
        print(f"  Tablas presentes: {', '.join(table_names)}")
        
        # Contar registros
        for table in table_names:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"    - {table}: {count} registros")
        
        conn.close()
    except Exception as e:
        print_check(False, f"Error al leer BD: {e}")

# 8. Verificar configuración
print("\n8️⃣  CONFIGURACIÓN")
print("-" * 70)

# Verificar variables de entorno
venv_configured = "VIRTUAL_ENV" in os.environ
print_check(venv_configured, f"Entorno virtual: {'Activado' if venv_configured else 'No activado'}")

virustotal_key = os.environ.get("VIRUSTOTAL_API_KEY")
print_check(
    virustotal_key is not None,
    f"API Key VirusTotal: {'Configurada' if virustotal_key else 'No configurada (opcional)'}"
)

# 9. Amenazas detectables
print("\n9️⃣  PATRONES DE DETECCIÓN")
print("-" * 70)

try:
    from src.database import MalwareDatabase
    
    categories = len(MalwareDatabase.MALICIOUS_PATTERNS)
    total_patterns = sum(len(p) for p in MalwareDatabase.MALICIOUS_PATTERNS.values())
    dangerous_ext = len(MalwareDatabase.DANGEROUS_EXTENSIONS)
    known_malware = len(MalwareDatabase.MALWARE_SIGNATURES)
    
    print(f"  Categorías de amenaza: {categories}")
    print(f"  Patrones maliciosos: {total_patterns}")
    print(f"  Extensiones peligrosas: {dangerous_ext}")
    print(f"  Hashes malware conocidos: {known_malware}")
except:
    pass

# 10. Comandos disponibles
print("\n🔟 COMANDOS DISPONIBLES")
print("-" * 70)

commands = [
    "python antivirus.py (menú interactivo)",
    "python antivirus.py archivo.py (escaneo)",
    "python antivirus.py --help (todos los comandos)",
    "python antivirus.py --stats (estadísticas)",
    "python antivirus.py --history (historial)",
    "python antivirus.py --list-quarantine (cuarentena)",
    "python antivirus.py --watch-downloads (monitoreo)",
    "python antivirus.py --export-csv archivo.csv (reportes)",
    "python antivirus.py --update-signatures (actualizar)",
    "python antivirus.py --virustotal archivo (VirusTotal)"
]

for cmd in commands:
    print(f"  • {cmd}")

# Resumen final
print_header("RESUMEN FINAL")

all_checks = {**dirs_check, **files_check, **docs_check}
passed = sum(all_checks.values())
total = len(all_checks)

print(f"\nVerificaciones completadas: {passed}/{total}")
print(f"Estado: {'✅ LISTO PARA USAR' if passed == total else '⚠️  REVISAR ERRORES'}\n")

if passed == total:
    print("Para empezar:")
    print("  1. Ver documentación: README.md")
    print("  2. Ejecutar demostración: bash demo.sh")
    print("  3. Escanear archivo: python antivirus.py archivo.py")
    print("  4. Ver menú: python antivirus.py --help\n")
else:
    print("Algunos archivos no se encontraron.")
    print("Asegúrate de estar en la carpeta correcta del proyecto.\n")

print(f"{'═'*70}\n")
