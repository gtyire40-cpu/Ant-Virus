#!/usr/bin/env python3
"""
Punto de entrada CLI para el escáner de antivirus
"""

import sys
from src.cli import main

if __name__ == "__main__":
    # Soportar comandos adicionales
    if len(sys.argv) > 1:
        if sys.argv[1] == "--quarantine" and len(sys.argv) > 2:
            from src.scanner import AntivirusScanner
            scanner = AntivirusScanner()
            result = scanner.quarantine_file(sys.argv[2])
            print(f"\n{result['message']}")
        elif sys.argv[1] == "--trust" and len(sys.argv) > 2:
            from src.scanner import AntivirusScanner
            scanner = AntivirusScanner()
            result = scanner.add_to_whitelist(sys.argv[2])
            print(f"\n{result['message']}")
        elif sys.argv[1] == "--history":
            from src.scanner import AntivirusScanner
            scanner = AntivirusScanner()
            history = scanner.get_scan_history(20)
            print("\n📋 HISTORIAL DE ESCANEOS RECIENTES:\n")
            if history:
                for filepath, is_safe, threats, timestamp in history:
                    status = "✓" if is_safe else "✗"
                    print(f"{status} {filepath}")
                    print(f"  Amenazas: {threats} | {timestamp}\n")
            else:
                print("No hay escaneos guardados")
        elif sys.argv[1] == "--stats":
            from src.scanner import AntivirusScanner
            scanner = AntivirusScanner()
            stats = scanner.get_statistics()
            print("\n📈 ESTADÍSTICAS GENERALES:\n")
            print(f"   Total de archivos escaneados: {stats['total_scans']}")
            print(f"   Archivos seguros: {stats['safe_files']}")
            print(f"   Archivos infectados: {stats['infected_files']}")
            print(f"   Tasa de detección: {stats['detection_rate']:.1f}%\n")
        elif sys.argv[1] == "--list-quarantine":
            from src.scanner import AntivirusScanner
            scanner = AntivirusScanner()
            files = scanner.list_quarantine()
            print("\n🔒 ARCHIVOS EN CUARENTENA:\n")
            if files:
                for i, file in enumerate(files, 1):
                    print(f"   {i}. {file}")
            else:
                print("   Carpeta de cuarentena vacía")
            print()
        elif sys.argv[1] == "--restore" and len(sys.argv) > 2:
            from src.scanner import AntivirusScanner
            import os
            scanner = AntivirusScanner()
            filename = sys.argv[2]
            # Restaurar a la carpeta de descargas o actual
            dest = os.path.expanduser("~/Descargas") if os.path.exists(os.path.expanduser("~/Descargas")) else "."
            dest_path = os.path.join(dest, filename)
            result = scanner.restore_from_quarantine(filename, dest_path)
            print(f"\n{result['message']}\n")
        elif sys.argv[1] == "--export-csv":
            from src.database import ScanHistory
            output = sys.argv[2] if len(sys.argv) > 2 else "scan_history.csv"
            file = ScanHistory.export_to_csv(output)
            print(f"\n✅ Historial exportado a: {file}\n")
        elif sys.argv[1] == "--update-signatures":
            from src.database import SignatureUpdater
            print("\n🔄 GESTOR DE FIRMAS DE MALWARE\n")
            SignatureUpdater.print_signature_stats()
            print("\n📥 Descargando firmas más recientes...")
            if SignatureUpdater.update_signatures():
                print("✅ Firmas actualizadas correctamente\n")
            else:
                print("⚠️ No se pudo conectar. Usando firmas locales.\n")
        elif sys.argv[1] == "--watch" and len(sys.argv) > 2:
            from src.watcher import FileWatcher
            FileWatcher.watch_directory(sys.argv[2])
        elif sys.argv[1] == "--watch-downloads":
            from src.watcher import FileWatcher
            FileWatcher.watch_downloads()
        elif sys.argv[1] == "--virustotal" and len(sys.argv) > 2:
            from src.virustotal import VirusTotalScanner
            from src.utils import FileAnalyzer
            filepath = sys.argv[2]
            
            print("\n🌍 ESCÁNER VIRUSTOTAL")
            print(f"\n   Archivo: {filepath}")
            
            # Obtener hash
            file_hash = FileAnalyzer.get_file_hash(filepath)
            print(f"   Hash: {file_hash}\n")
            
            if not VirusTotalScanner.is_configured():
                print("⚠️ VirusTotal no configurado")
                VirusTotalScanner.get_setup_instructions()
            else:
                print("⏳ Buscando en VirusTotal...")
                result = VirusTotalScanner.scan_file_by_hash(file_hash)
                
                if result:
                    print(f"✓ Detectado en VirusTotal")
                    print(f"  Motores: {result.get('engines', 0)}")
                    print(f"  Detecciones: {result.get('detections', 0)}\n")
                else:
                    print("Intenta subir para análisis completo...")
                    result = VirusTotalScanner.upload_and_scan(filepath)
                    if result:
                        print(f"✅ Archivo enviado para análisis\n")
        elif sys.argv[1] == "--help":
            print("""
╔══════════════════════════════════════════════════════════════╗
║           ESCÁNER DE ANTIVIRUS - COMANDOS COMPLETOS          ║
╚══════════════════════════════════════════════════════════════╝

📋 USO BÁSICO:
  python antivirus.py                    # Menú interactivo
  python antivirus.py archivo.py         # Escanear archivo
  python antivirus.py carpeta/           # Escanear carpeta

🔍 ESCANEO Y ANÁLISIS:
  python antivirus.py --virustotal FILE   # Usar VirusTotal API
  python antivirus.py --watch DIR         # Monitoreo en tiempo real
  python antivirus.py --watch-downloads   # Monitorear Descargas

🔒 CUARENTENA Y WHITELIST:
  python antivirus.py --quarantine FILE   # Poner en cuarentena
  python antivirus.py --list-quarantine   # Listar en cuarentena
  python antivirus.py --restore FILE      # Restaurar archivo
  python antivirus.py --trust FILE        # Agregar a whitelist

📊 REPORTES E HISTORIAL:
  python antivirus.py --history           # Ver últimos escaneos
  python antivirus.py --stats             # Ver estadísticas
  python antivirus.py --export-csv FILE   # Exportar a CSV

⚙️ MANTENIMIENTO:
  python antivirus.py --update-signatures # Actualizar firmas
  python antivirus.py --help              # Este mensaje

EJEMPLO:
  python antivirus.py --watch ~/Descargas
  python antivirus.py --export-csv reportes.csv
  python antivirus.py --update-signatures
            """)
        else:
            # Modo normal
            main()
    else:
        main()

