"""
Módulo de escaneo en tiempo real (watchdog)
"""

import os
import time
from pathlib import Path
from typing import Callable, Optional
from src.scanner import AntivirusScanner


class FileWatcher:
    """Monitorea cambios en carpeta y escanea automáticamente"""
    
    def __init__(self, directory: str, on_file_added: Optional[Callable] = None):
        """
        Inicializa el watcher
        
        Args:
            directory: Carpeta a monitorear
            on_file_added: Callback cuando hay archivo nuevo
        """
        self.directory = os.path.expanduser(directory)
        self.on_file_added = on_file_added
        self.scanner = AntivirusScanner()
        self.known_files = set(self._get_files())
    
    def _get_files(self) -> list:
        """Obtiene lista de archivos en directorio"""
        try:
            return [f for f in os.listdir(self.directory) 
                   if os.path.isfile(os.path.join(self.directory, f))]
        except:
            return []
    
    def start(self, interval: int = 5, duration: Optional[int] = None):
        """
        Inicia el monitoreo
        
        Args:
            interval: Segundos entre chequeos
            duration: Duración total en segundos (None = infinito)
        """
        print(f"\n👁️ MONITOREO EN TIEMPO REAL")
        print(f"   Carpeta: {self.directory}")
        print(f"   Intervalo: {interval} segundos")
        print(f"   Presiona Ctrl+C para salir\n")
        
        start_time = time.time()
        
        try:
            while True:
                # Verificar si excedió duración
                if duration and (time.time() - start_time) > duration:
                    break
                
                current_files = set(self._get_files())
                new_files = current_files - self.known_files
                
                if new_files:
                    print(f"\n📁 Archivos nuevos detectados: {len(new_files)}")
                    for filename in new_files:
                        filepath = os.path.join(self.directory, filename)
                        print(f"\n⏳ Escaneando: {filename}")
                        
                        result = self.scanner.scan_file(filepath)
                        
                        if result.get('is_safe'):
                            print(f"✓ {filename} - SEGURO")
                        else:
                            print(f"✗ {filename} - PELIGRO DETECTADO")
                            threats = result.get('threats', [])
                            if threats:
                                print(f"   Amenazas: {len(threats)}")
                                for threat in threats[:3]:
                                    print(f"   • {threat.get('description', 'Desconocida')}")
                        
                        # Callback
                        if self.on_file_added:
                            self.on_file_added(filepath, result)
                    
                    self.known_files = current_files
                
                time.sleep(interval)
        
        except KeyboardInterrupt:
            print("\n\n👋 Monitoreo finalizado")
    
    @staticmethod
    def watch_downloads(duration: Optional[int] = None):
        """Monitorea carpeta de Descargas"""
        downloads = os.path.expanduser("~/Descargas")
        if not os.path.exists(downloads):
            print("❌ Carpeta de Descargas no encontrada")
            return
        
        watcher = FileWatcher(downloads)
        watcher.start(interval=10, duration=duration)
    
    @staticmethod
    def watch_directory(directory: str, duration: Optional[int] = None):
        """Monitorea directorio específico"""
        if not os.path.isdir(directory):
            print(f"❌ Directorio no encontrado: {directory}")
            return
        
        watcher = FileWatcher(directory)
        watcher.start(interval=5, duration=duration)


class ScheduledScanner:
    """Ejecuta escaneos programados"""
    
    def __init__(self, directory: str, interval_hours: int = 24):
        """
        Inicializa escáner programado
        
        Args:
            directory: Carpeta a escanear
            interval_hours: Horas entre escaneos
        """
        self.directory = os.path.expanduser(directory)
        self.interval = interval_hours * 3600
        self.scanner = AntivirusScanner()
    
    def start(self, duration: Optional[int] = None):
        """
        Inicia escaneos programados
        
        Args:
            duration: Duración total en segundos
        """
        print(f"\n⏰ ESCANEOS PROGRAMADOS")
        print(f"   Carpeta: {self.directory}")
        print(f"   Intervalo: {self.interval/3600:.0f} horas")
        print(f"   Presiona Ctrl+C para salir\n")
        
        start_time = time.time()
        next_scan = time.time()
        
        try:
            while True:
                if duration and (time.time() - start_time) > duration:
                    break
                
                if time.time() >= next_scan:
                    print(f"\n📅 Iniciando escaneo programado...")
                    result = self.scanner.scan_directory(self.directory)
                    
                    print(f"   Archivos: {result.get('files_scanned', 0)}")
                    print(f"   Seguros: {result.get('safe_files', 0)}")
                    print(f"   Amenazas: {result.get('threats_found', 0)}")
                    
                    next_scan = time.time() + self.interval
                    próximos = self.interval / 3600
                    print(f"   Próximo escaneo en {próximos:.0f} horas\n")
                
                time.sleep(300)  # Chequear cada 5 minutos
        
        except KeyboardInterrupt:
            print("\n\n👋 Escaneos programados finalizados")
