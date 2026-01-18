"""
Módulo de utilidades para el escáner de antivirus
"""

import hashlib
import os
import magic
import zipfile
import tempfile
from typing import Dict, Tuple, List


class ArchiveAnalyzer:
    """Analiza archivos comprimidos"""
    
    SUPPORTED_FORMATS = ['.zip', '.tar', '.gz']
    
    @staticmethod
    def extract_archive(filepath: str) -> List[Dict]:
        """
        Extrae y obtiene archivos de un comprimido
        
        Args:
            filepath: Ruta del archivo comprimido
            
        Returns:
            Lista con información de archivos dentro
        """
        files = []
        
        try:
            if filepath.lower().endswith('.zip'):
                with zipfile.ZipFile(filepath, 'r') as z:
                    for info in z.infolist():
                        files.append({
                            'name': info.filename,
                            'size': info.file_size,
                            'compressed_size': info.compress_size,
                            'is_dir': info.is_dir()
                        })
        except Exception as e:
            pass
        
        return files
    
    @staticmethod
    def is_archive(filepath: str) -> bool:
        """Verifica si es archivo comprimido"""
        _, ext = os.path.splitext(filepath.lower())
        return ext in ArchiveAnalyzer.SUPPORTED_FORMATS
    
    @staticmethod
    def has_suspicious_files(filepath: str) -> Tuple[bool, List[str]]:
        """Detecta archivos sospechosos dentro del comprimido"""
        suspicious = []
        dangerous_extensions = ['.exe', '.dll', '.vbs', '.bat', '.cmd', '.scr', '.ps1']
        
        try:
            if filepath.lower().endswith('.zip'):
                with zipfile.ZipFile(filepath, 'r') as z:
                    for name in z.namelist():
                        _, ext = os.path.splitext(name.lower())
                        if ext in dangerous_extensions:
                            suspicious.append(name)
        except:
            pass
        
        return len(suspicious) > 0, suspicious


class FileAnalyzer:
    """Analiza archivos para obtener información"""

    @staticmethod
    def get_file_hash(filepath: str, algorithm: str = "md5") -> str:
        """
        Calcula el hash de un archivo
        
        Args:
            filepath: Ruta del archivo
            algorithm: Algoritmo de hash (md5, sha256, etc.)
            
        Returns:
            Hash del archivo en formato hexadecimal
        """
        hasher = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def get_file_info(filepath: str) -> Dict[str, any]:
        """
        Obtiene información del archivo
        
        Args:
            filepath: Ruta del archivo
            
        Returns:
            Diccionario con información del archivo
        """
        try:
            file_stat = os.stat(filepath)
            file_type = magic.from_file(filepath, mime=True)
            
            return {
                "name": os.path.basename(filepath),
                "size": file_stat.st_size,
                "type": file_type,
                "path": filepath,
                "md5": FileAnalyzer.get_file_hash(filepath, "md5"),
                "sha256": FileAnalyzer.get_file_hash(filepath, "sha256")
            }
        except Exception as e:
            return {"error": str(e), "path": filepath}

    @staticmethod
    def is_suspicious_extension(filepath: str) -> Tuple[bool, str]:
        """
        Verifica si la extensión es sospechosa
        
        Args:
            filepath: Ruta del archivo
            
        Returns:
            Tupla (es_sospechoso, mensaje)
        """
        suspicious_extensions = {
            ".exe": "Ejecutable de Windows",
            ".dll": "Librería dinámica",
            ".vbs": "Script de Visual Basic",
            ".bat": "Script batch",
            ".cmd": "Comando de Windows",
            ".scr": "Protector de pantalla",
            ".pif": "Acceso directo MS-DOS",
            ".com": "Archivo ejecutable COM",
            ".prc": "Programa PalmOS",
            ".jar": "Archivo Java",
            ".zip": "Archivo comprimido",
            ".rar": "Archivo comprimido",
            ".7z": "Archivo 7-Zip"
        }
        
        _, ext = os.path.splitext(filepath.lower())
        
        if ext in suspicious_extensions:
            return True, suspicious_extensions[ext]
        
        return False, ""

    @staticmethod
    def analyze_file_content(filepath: str) -> Dict[str, any]:
        """
        Analiza el contenido del archivo buscando código malicioso
        
        Args:
            filepath: Ruta del archivo
            
        Returns:
            Diccionario con análisis del contenido
        """
        analysis = {
            "is_text": False,
            "is_executable": False,
            "suspicious_content": False,
            "details": ""
        }
        
        try:
            # Intentar leer como texto
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            analysis["is_text"] = True
            analysis["content"] = content[:10000]  # Primeros 10KB
            
            # Detectar tipo de código
            if any(ext in filepath.lower() for ext in ['.py', '.sh', '.bat', '.ps1', '.vbs', '.js']):
                analysis["is_executable"] = True
            
        except Exception as e:
            analysis["error"] = str(e)
        
        return analysis
    
    @staticmethod
    def get_file_size_info(filepath: str) -> str:
        """Obtiene información del tamaño del archivo"""
        size = os.path.getsize(filepath)
        
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.2f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.2f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.2f} GB"
