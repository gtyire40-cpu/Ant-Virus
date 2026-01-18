"""
CLI para el escáner de antivirus (sin requerimientos de GUI)
"""

import os
import sys
from .scanner import AntivirusScanner


class AntivirusCLI:
    """Interfaz de línea de comandos para el antivirus"""
    
    def __init__(self):
        self.scanner = AntivirusScanner()
    
    def print_banner(self):
        """Imprime el banner de la aplicación"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                  ESCÁNER DE ANTIVIRUS v1.0.0                  ║
║              Detecta archivos maliciosos potenciales           ║
╚═══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def print_result(self, result):
        """Imprime los resultados del escaneo"""
        print("\n" + "="*70)
        print("RESULTADO DEL ESCANEO")
        print("="*70 + "\n")
        
        if "error" in result:
            print(f"❌ Error: {result['error']}")
            return
        
        if "directory" in result:
            self._print_directory_result(result)
        else:
            self._print_file_result(result)
    
    def _print_file_result(self, result):
        """Imprime resultado de archivo"""
        print(f"📄 Archivo: {result.get('filename', 'N/A')}")
        print(f"   Ruta: {result.get('filepath', 'N/A')}")
        print(f"   Tamaño: {result.get('size', 'N/A')}")
        print(f"   Tipo: {result.get('file_type', 'N/A')}")
        
        if result.get('is_safe'):
            print("\n   ✓ ARCHIVO SEGURO\n")
        else:
            print("\n   ✗ ARCHIVO POTENCIALMENTE PELIGROSO\n")
            if result.get('threats'):
                print(f"   Amenazas detectadas ({len(result['threats'])}):\n")
                for i, threat in enumerate(result['threats'], 1):
                    print(f"   [{i}] {threat['type']}")
                    print(f"       {threat['description']}")
                    
                    # Mostrar patrones encontrados si es código malicioso
                    if threat['type'] == 'malicious_code' and 'found_patterns' in threat:
                        patterns = threat['found_patterns'][:5]  # Primeros 5
                        print(f"       Patrones encontrados: {', '.join(patterns)}")
                    
                    print()
        
        if result.get('md5'):
            print(f"   MD5: {result['md5']}")
        if result.get('sha256'):
            print(f"   SHA256: {result['sha256'][:32]}...")
    
    def _print_directory_result(self, result):
        """Imprime resultado de carpeta"""
        print(f"📁 Carpeta: {result.get('directory', 'N/A')}")
        print(f"   Archivos escaneados: {result.get('files_scanned', 0)}")
        print(f"   Archivos seguros: {result.get('safe_files', 0)}")
        print(f"   Amenazas encontradas: {result.get('threats_found', 0)}")
        
        if result.get('threats_found', 0) > 0:
            print("\n   Archivos con amenazas:")
            for file_result in result.get('file_results', []):
                if not file_result.get('is_safe', True):
                    print(f"   ✗ {file_result.get('filename')}")
                    for threat in file_result.get('threats', []):
                        print(f"     - {threat['description']}")
    
    def run_interactive(self):
        """Modo interactivo"""
        self.print_banner()
        
        while True:
            print("\n" + "-"*70)
            print("OPCIONES:")
            print("1. Escanear archivo")
            print("2. Escanear carpeta")
            print("3. Ver resumen")
            print("4. Ver historial de escaneos")
            print("5. Ver cuarentena")
            print("6. Agregar a whitelist")
            print("7. Estadísticas generales")
            print("8. Salir")
            print("-"*70)
            
            choice = input("\nSelecciona una opción (1-8): ").strip()
            
            if choice == "1":
                path = input("Ruta del archivo: ").strip()
                if os.path.isfile(path):
                    print("\n⏳ Escaneando...")
                    result = self.scanner.scan_file(path)
                    self.print_result(result)
                else:
                    print("❌ Archivo no encontrado")
            
            elif choice == "2":
                path = input("Ruta de la carpeta: ").strip()
                if os.path.isdir(path):
                    print("\n⏳ Escaneando...")
                    result = self.scanner.scan_directory(path)
                    self.print_result(result)
                else:
                    print("❌ Carpeta no encontrada")
            
            elif choice == "3":
                summary = self.scanner.get_scan_summary()
                print("\n📊 RESUMEN DE ESCANEOS:")
                print(f"   Total de escaneos: {summary['total_scans']}")
                print(f"   Archivos seguros: {summary['safe_files']}")
                print(f"   Archivos infectados: {summary['infected_files']}")
                print(f"   Tasa de detección: {summary['detection_rate']}")
            
            elif choice == "4":
                print("\n📋 HISTORIAL DE ESCANEOS:")
                history = self.scanner.get_scan_history(10)
                if history:
                    for filepath, is_safe, threats, timestamp in history:
                        status = "✓" if is_safe else "✗"
                        print(f"{status} {filepath} - {threats} amenazas - {timestamp}")
                else:
                    print("   No hay escaneos guardados")
            
            elif choice == "5":
                quarantine_files = self.scanner.list_quarantine()
                print("\n🔒 ARCHIVOS EN CUARENTENA:")
                if quarantine_files:
                    for i, file in enumerate(quarantine_files, 1):
                        print(f"   {i}. {file}")
                else:
                    print("   Carpeta de cuarentena vacía")
            
            elif choice == "6":
                path = input("Ruta del archivo a confiar: ").strip()
                if os.path.isfile(path):
                    result = self.scanner.add_to_whitelist(path)
                    print(f"✅ {result['message']}")
                else:
                    print("❌ Archivo no encontrado")
            
            elif choice == "7":
                stats = self.scanner.get_statistics()
                print("\n📈 ESTADÍSTICAS GENERALES:")
                print(f"   Total de archivos escaneados: {stats['total_scans']}")
                print(f"   Archivos seguros: {stats['safe_files']}")
                print(f"   Archivos infectados: {stats['infected_files']}")
                print(f"   Tasa de detección: {stats['detection_rate']:.1f}%")
            
            elif choice == "8":
                print("\n👋 ¡Hasta luego!")
                break
            
            else:
                print("❌ Opción inválida")


def main():
    """Función principal"""
    cli = AntivirusCLI()
    
    if len(sys.argv) > 1:
        # Modo de línea de comandos con argumentos
        path = sys.argv[1]
        cli.print_banner()
        print(f"\n⏳ Escaneando: {path}")
        
        if os.path.isfile(path):
            result = cli.scanner.scan_file(path)
        elif os.path.isdir(path):
            result = cli.scanner.scan_directory(path)
        else:
            print(f"❌ Ruta no encontrada: {path}")
            return
        
        cli.print_result(result)
    else:
        # Modo interactivo
        cli.run_interactive()


if __name__ == "__main__":
    main()
