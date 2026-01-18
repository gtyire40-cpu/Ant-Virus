"""
Integración con VirusTotal API para análisis avanzado
"""

import requests
import hashlib
import time
from typing import Dict, Optional


class VirusTotalScanner:
    """Escáner usando VirusTotal API"""
    
    # API gratuita - reemplazar con clave propia desde https://www.virustotal.com/gui/
    API_KEY = "paste_your_api_key_here"
    API_URL = "https://www.virustotal.com/api/v3"
    
    @classmethod
    def is_configured(cls) -> bool:
        """Verifica si API está configurada"""
        return cls.API_KEY != "paste_your_api_key_here"
    
    @classmethod
    def set_api_key(cls, api_key: str):
        """Configura la API key"""
        cls.API_KEY = api_key
    
    @classmethod
    def scan_file_by_hash(cls, file_hash: str, hash_type: str = "md5") -> Optional[Dict]:
        """
        Busca un archivo por su hash en VirusTotal
        
        Args:
            file_hash: Hash del archivo (MD5, SHA256, etc)
            hash_type: Tipo de hash
            
        Returns:
            Diccionario con resultados o None
        """
        if not cls.is_configured():
            return None
        
        try:
            headers = {"x-apikey": cls.API_KEY}
            url = f"{cls.API_URL}/files/{file_hash}"
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                
                return {
                    "status": "found",
                    "detected": stats['malicious'] > 0,
                    "detections": stats['malicious'],
                    "total_engines": stats['malicious'] + stats['suspicious'] + stats['undetected'],
                    "verdicts": {
                        "malicious": stats['malicious'],
                        "suspicious": stats['suspicious'],
                        "undetected": stats['undetected']
                    }
                }
            elif response.status_code == 404:
                return {"status": "not_found", "message": "Hash no encontrado en VirusTotal"}
            else:
                return {"status": "error", "message": f"Error: {response.status_code}"}
        
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    @classmethod
    def upload_and_scan(cls, filepath: str) -> Optional[Dict]:
        """
        Sube un archivo a VirusTotal para escaneo
        
        Args:
            filepath: Ruta del archivo
            
        Returns:
            Diccionario con ID de análisis
        """
        if not cls.is_configured():
            return None
        
        try:
            headers = {"x-apikey": cls.API_KEY}
            url = f"{cls.API_URL}/files"
            
            with open(filepath, 'rb') as f:
                files = {'file': f}
                response = requests.post(url, headers=headers, files=files, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "queued",
                    "analysis_id": data['data']['id'],
                    "message": "Archivo enviado para análisis"
                }
            else:
                return {"status": "error", "message": f"Error: {response.status_code}"}
        
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    @classmethod
    def get_analysis_results(cls, analysis_id: str) -> Optional[Dict]:
        """
        Obtiene resultados del análisis
        
        Args:
            analysis_id: ID del análisis
            
        Returns:
            Resultados del escaneo
        """
        if not cls.is_configured():
            return None
        
        try:
            headers = {"x-apikey": cls.API_KEY}
            url = f"{cls.API_URL}/analyses/{analysis_id}"
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['stats']
                
                return {
                    "status": data['data']['attributes']['status'],
                    "detections": stats['malicious'],
                    "suspicious": stats['suspicious'],
                    "undetected": stats['undetected'],
                    "total": sum(stats.values())
                }
            else:
                return {"status": "error"}
        
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    @classmethod
    def get_setup_instructions(cls) -> str:
        """Retorna instrucciones para configurar VirusTotal"""
        return """
╔════════════════════════════════════════════════════════════════╗
║           CONFIGURAR VIRUSTOTAL API                            ║
╚════════════════════════════════════════════════════════════════╝

1. Ir a: https://www.virustotal.com/gui/home/upload

2. Crear cuenta (o iniciar sesión)

3. Ir a: https://www.virustotal.com/gui/settings/api

4. Copiar tu API key

5. Configurar en antivirus:
   python antivirus.py --set-virustotal YOUR_API_KEY

6. Listo! Ahora puedes usar:
   python antivirus.py --virustotal archivo.exe
   
Beneficios:
✓ Análisis con 70+ antivirus simultáneamente
✓ Detección de malware conocido a nivel mundial
✓ Muy preciso para archivos sospechosos
✓ API gratuita con límites generosos

Nota: La API gratuita permite 4 requests/minuto
        """
