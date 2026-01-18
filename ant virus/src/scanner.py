"""
Módulo principal de escaneo de antivirus
"""

import os
import shutil
from typing import Dict, List, Tuple
from .database import MalwareDatabase, ScanHistory
from .utils import FileAnalyzer, ArchiveAnalyzer


class AntivirusScanner:
    """Escáner de antivirus con múltiples métodos de detección"""
    
    QUARANTINE_DIR = "./quarantine"
    
    def __init__(self):
        self.scan_results = []
        self.file_analyzer = FileAnalyzer()
        self.db = MalwareDatabase()
        self.archive_analyzer = ArchiveAnalyzer()
        os.makedirs(self.QUARANTINE_DIR, exist_ok=True)
    
    def scan_file(self, filepath: str) -> Dict:
        """
        Escanea un archivo individual
        
        Args:
            filepath: Ruta del archivo a escanear
            
        Returns:
            Diccionario con resultados del escaneo
        """
        if not os.path.exists(filepath):
            return {
                "status": "error",
                "message": f"El archivo no existe: {filepath}"
            }
        
        if os.path.isdir(filepath):
            return self.scan_directory(filepath)
        
        # NUEVO: Verificar si es archivo comprimido
        if self.archive_analyzer.is_archive(filepath):
            return self._scan_archive(filepath)
        
        result = {
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "size": self.file_analyzer.get_file_size_info(filepath),
            "threats": [],
            "is_safe": True
        }
        
        # Obtener información del archivo
        file_info = self.file_analyzer.get_file_info(filepath)
        
        if "error" in file_info:
            result["status"] = "error"
            result["message"] = file_info["error"]
            return result
        
        # Análisis 1: Verificar extensión peligrosa
        is_dangerous, reason = self.file_analyzer.is_suspicious_extension(filepath)
        if is_dangerous:
            result["threats"].append({
                "type": "suspicious_extension",
                "description": f"Extensión sospechosa detectada: {reason}"
            })
            result["is_safe"] = False
        
        # Análisis 2: Verificar contra base de datos de firmas
        md5_hash = file_info.get("md5")
        if self.db.is_known_malware(md5_hash):
            malware_name = self.db.get_malware_name(md5_hash)
            result["threats"].append({
                "type": "known_malware",
                "description": f"Malware conocido detectado: {malware_name}",
                "hash": md5_hash
            })
            result["is_safe"] = False
        
        # Análisis 3: Verificar patrones sospechosos en el contenido
        try:
            with open(filepath, "rb") as f:
                # Leer solo los primeros 100KB para análisis rápido
                file_content_bytes = f.read(100 * 1024)
                
                # Verificar con patrones básicos
                basic_patterns = [b"cmd.exe", b"powershell", b"rundll32", b"regsvr32"]
                if any(pattern in file_content_bytes for pattern in basic_patterns):
                    result["threats"].append({
                        "type": "basic_threat_pattern",
                        "description": "Se detectaron patrones de amenaza básicos"
                    })
                    result["is_safe"] = False
        except Exception as e:
            pass  # Ignorar errores en este análisis
        
        # Análisis 4: Análisis profundo del código si es un archivo de script
        content_analysis = self.file_analyzer.analyze_file_content(filepath)
        
        if content_analysis.get("is_text") and content_analysis.get("is_executable"):
            # Es un script ejecutable - analizar el código en profundidad
            file_content_str = content_analysis.get("content", "")
            malicious_code = self.db.analyze_malicious_code(file_content_str)
            
            if malicious_code:
                result["is_safe"] = False
                for category, patterns in malicious_code.items():
                    description = self.db.get_threat_description(category)
                    result["threats"].append({
                        "type": "malicious_code",
                        "category": category,
                        "description": description,
                        "found_patterns": patterns
                    })
        
        # Agregar información adicional
        result["file_type"] = file_info.get("type", "desconocido")
        result["md5"] = md5_hash
        result["sha256"] = file_info.get("sha256")
        
        self.scan_results.append(result)
        
        # Guardar en historial
        ScanHistory.save_scan(filepath, result.get("is_safe", True), len(result.get("threats", [])))
        
        return result
    
    def scan_directory(self, directory: str, recursive: bool = True) -> Dict:
        """
        Escanea una carpeta completa
        
        Args:
            directory: Ruta de la carpeta a escanear
            recursive: Si escanear recursivamente
            
        Returns:
            Diccionario con resultados del escaneo
        """
        results = {
            "directory": directory,
            "files_scanned": 0,
            "threats_found": 0,
            "safe_files": 0,
            "file_results": []
        }
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    filepath = os.path.join(root, file)
                    file_result = self.scan_file(filepath)
                    
                    if file_result.get("is_safe") is not None:
                        results["files_scanned"] += 1
                        results["file_results"].append(file_result)
                        
                        if file_result.get("is_safe"):
                            results["safe_files"] += 1
                        else:
                            results["threats_found"] += 1
                
                # Si no es recursivo, salir después del primer nivel
                if not recursive:
                    break
        
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def get_scan_summary(self) -> Dict:
        """Obtiene un resumen de los escaneos realizados"""
        total_scans = len(self.scan_results)
        safe_files = sum(1 for r in self.scan_results if r.get("is_safe", False))
        infected_files = total_scans - safe_files
        
        return {
            "total_scans": total_scans,
            "safe_files": safe_files,
            "infected_files": infected_files,
            "detection_rate": f"{(infected_files / total_scans * 100):.1f}%" if total_scans > 0 else "0%"
        }
    
    def clear_results(self):
        """Limpia los resultados del escaneo"""
        self.scan_results = []
    
    def quarantine_file(self, filepath: str) -> Dict:
        """
        Mueve un archivo a la carpeta de cuarentena
        
        Args:
            filepath: Ruta del archivo a aislar
            
        Returns:
            Diccionario con resultado de la cuarentena
        """
        if not os.path.exists(filepath):
            return {"status": "error", "message": "Archivo no encontrado"}
        
        try:
            filename = os.path.basename(filepath)
            quarantine_path = os.path.join(self.QUARANTINE_DIR, filename)
            
            # Si ya existe, agregar número
            counter = 1
            base_name, ext = os.path.splitext(filename)
            while os.path.exists(quarantine_path):
                quarantine_path = os.path.join(
                    self.QUARANTINE_DIR, 
                    f"{base_name}_{counter}{ext}"
                )
                counter += 1
            
            shutil.move(filepath, quarantine_path)
            
            return {
                "status": "success",
                "message": f"Archivo puesto en cuarentena: {quarantine_path}",
                "original_path": filepath,
                "quarantine_path": quarantine_path
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def add_to_whitelist(self, filepath: str, md5_hash: str = None) -> Dict:
        """
        Agrega un archivo a la whitelist (archivos confiables)
        
        Args:
            filepath: Ruta del archivo
            md5_hash: Hash MD5 (si no se proporciona, se calcula)
            
        Returns:
            Diccionario con resultado
        """
        if md5_hash is None:
            md5_hash = self.file_analyzer.get_file_hash(filepath, "md5")
        
        ScanHistory.add_to_whitelist(md5_hash, filepath, "Manual trust")
        
        return {
            "status": "success",
            "message": f"Archivo agregado a whitelist: {os.path.basename(filepath)}",
            "md5": md5_hash
        }
    
    def check_whitelist(self, md5_hash: str) -> bool:
        """Verifica si un archivo está en whitelist"""
        return ScanHistory.is_whitelisted(md5_hash)
    
    def get_scan_history(self, limit: int = 10) -> List:
        """Obtiene historial de escaneos recientes"""
        return ScanHistory.get_recent_scans(limit)
    
    def get_statistics(self) -> Dict:
        """Obtiene estadísticas generales"""
        return ScanHistory.get_statistics()
    
    def list_quarantine(self) -> List[str]:
        """Lista archivos en cuarentena"""
        if os.path.exists(self.QUARANTINE_DIR):
            return os.listdir(self.QUARANTINE_DIR)
        return []
    
    def restore_from_quarantine(self, filename: str, destination: str) -> Dict:
        """
        Restaura un archivo desde cuarentena
        
        Args:
            filename: Nombre del archivo en cuarentena
            destination: Ruta de destino
            
        Returns:
            Diccionario con resultado
        """
        quarantine_path = os.path.join(self.QUARANTINE_DIR, filename)
        
        if not os.path.exists(quarantine_path):
            return {"status": "error", "message": "Archivo no encontrado en cuarentena"}
        
        try:
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            shutil.move(quarantine_path, destination)
            
            return {
                "status": "success",
                "message": f"Archivo restaurado: {destination}",
                "path": destination
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _scan_archive(self, filepath: str) -> Dict:
        """
        Escanea un archivo comprimido
        
        Args:
            filepath: Ruta del archivo comprimido
            
        Returns:
            Diccionario con resultados
        """
        result = {
            "filepath": filepath,
            "filename": os.path.basename(filepath),
            "file_type": "archive",
            "threats": [],
            "is_safe": True,
            "archive_contents": []
        }
        
        # Verificar extensión del archivo comprimido
        is_dangerous, reason = self.file_analyzer.is_suspicious_extension(filepath)
        if is_dangerous:
            result["threats"].append({
                "type": "suspicious_archive",
                "description": f"Archivo comprimido sospechoso: {reason}"
            })
        
        # Intentar extraer y analizar
        try:
            extracted_files = self.archive_analyzer.extract_archive(filepath)
            
            for file_info in extracted_files:
                if file_info.get('is_dir'):
                    continue
                    
                filename = file_info.get('name')  # Cambiar de 'filename' a 'name'
                if filename:
                    result["archive_contents"].append(filename)
                    
                    # Verificar extensión dentro del archivo comprimido
                    ext_dangerous, ext_reason = self.file_analyzer.is_suspicious_extension(filename)
                    if ext_dangerous:
                        result["threats"].append({
                            "type": "suspicious_file_in_archive",
                            "description": f"Archivo peligroso dentro del comprimido: {filename} ({ext_reason})",
                            "file": filename
                        })
                        result["is_safe"] = False
            
            # Verificar si tiene archivos sospechosos
            has_suspicious, suspicious_files = self.archive_analyzer.has_suspicious_files(filepath)
            if has_suspicious:
                result["threats"].append({
                    "type": "suspicious_archive_content",
                    "description": "El archivo contiene ficheros con extensiones peligrosas",
                    "suspicious_files": suspicious_files
                })
                result["is_safe"] = False
        
        except Exception as e:
            result["threats"].append({
                "type": "archive_error",
                "description": f"Error al analizar archivo: {str(e)}"
            })
        
        # Guardar en historial
        ScanHistory.save_scan(filepath, result.get("is_safe", True), len(result.get("threats", [])))
        
        return result

