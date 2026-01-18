"""
Base de datos de firmas de malware conocidas
"""

from typing import Dict
import sqlite3
import os
from datetime import datetime

class ScanHistory:
    """Gestiona historial de escaneos"""
    
    DB_FILE = "scan_history.db"
    
    @classmethod
    def init_db(cls):
        """Inicializa la base de datos"""
        if not os.path.exists(cls.DB_FILE):
            conn = sqlite3.connect(cls.DB_FILE)
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filepath TEXT NOT NULL,
                    filename TEXT,
                    is_safe BOOLEAN,
                    threats_count INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                CREATE TABLE whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    md5_hash TEXT UNIQUE,
                    filepath TEXT,
                    reason TEXT,
                    added_date DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            conn.close()
    
    @classmethod
    def save_scan(cls, filepath: str, is_safe: bool, threats_count: int):
        """Guardar resultado de escaneo"""
        cls.init_db()
        conn = sqlite3.connect(cls.DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO scans (filepath, filename, is_safe, threats_count)
            VALUES (?, ?, ?, ?)
        """, (filepath, os.path.basename(filepath), is_safe, threats_count))
        
        conn.commit()
        conn.close()
    
    @classmethod
    def add_to_whitelist(cls, md5_hash: str, filepath: str, reason: str = "Manual"):
        """Agregar archivo a whitelist"""
        cls.init_db()
        conn = sqlite3.connect(cls.DB_FILE)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO whitelist (md5_hash, filepath, reason)
                VALUES (?, ?, ?)
            """, (md5_hash, filepath, reason))
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Ya existe
        finally:
            conn.close()
    
    @classmethod
    def is_whitelisted(cls, md5_hash: str) -> bool:
        """Verificar si está en whitelist"""
        cls.init_db()
        conn = sqlite3.connect(cls.DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT 1 FROM whitelist WHERE md5_hash = ?", (md5_hash,))
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    
    @classmethod
    def get_recent_scans(cls, limit: int = 10):
        """Obtener escaneos recientes"""
        cls.init_db()
        conn = sqlite3.connect(cls.DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT filepath, is_safe, threats_count, timestamp 
            FROM scans 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (limit,))
        
        results = cursor.fetchall()
        conn.close()
        return results
    
    @classmethod
    def get_statistics(cls):
        """Obtener estadísticas"""
        cls.init_db()
        conn = sqlite3.connect(cls.DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM scans")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM scans WHERE is_safe = 1")
        safe = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM scans WHERE is_safe = 0")
        infected = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_scans": total,
            "safe_files": safe,
            "infected_files": infected,
            "detection_rate": (infected / total * 100) if total > 0 else 0
        }
    
    @classmethod
    def export_to_csv(cls, output_file: str = "scan_history.csv"):
        """Exporta historial a CSV"""
        import csv
        from datetime import datetime
        
        cls.init_db()
        conn = sqlite3.connect(cls.DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT filepath, filename, is_safe, threats_count, timestamp 
            FROM scans 
            ORDER BY timestamp DESC
        """)
        
        rows = cursor.fetchall()
        conn.close()
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Archivo', 'Nombre', 'Seguro', 'Amenazas', 'Fecha/Hora'])
            
            for row in rows:
                filepath, filename, is_safe, threats_count, timestamp = row
                writer.writerow([
                    filepath,
                    filename,
                    '✓ Sí' if is_safe else '✗ No',
                    threats_count,
                    timestamp
                ])
        
        return output_file


class MalwareDatabase:
    """Base de datos de hashes de malware conocidos"""
    
    # Hashes MD5 de malware comunes (ejemplos)
    MALWARE_SIGNATURES = {
        "5d41402abc4b2a76b9719d911017c592": "Malware.Generic.A",
        "6512bd43d9caa6e02c990b0a82652dca": "Trojan.Generic.B",
        "c20ad4d76fe97759aa27a0c99bff6710": "Virus.Generic.C",
        "c51ce410c124a10e0db5e4b97fc2af39": "Worm.Generic.D",
        "aab3238922bcc25a6f3fb3d5c3712974": "Ransomware.Generic.E",
    }
    
    # Extensiones peligrosas
    DANGEROUS_EXTENSIONS = [
        ".exe", ".dll", ".vbs", ".bat", ".cmd", ".scr",
        ".pif", ".com", ".jar", ".app", ".deb"
    ]
    
    # Patrones maliciosos específicos detectables en código
    MALICIOUS_PATTERNS = {
        # Ejecución de comandos del sistema
        "command_execution": [
            b"os.system",
            b"subprocess.call",
            b"exec(",
            b"eval(",
            b"__import__",
            b"shell=True",
            b"cmd /c",
            b"powershell -",
            b"Start-Process"
        ],
        
        # Acceso a archivos del sistema
        "system_access": [
            b"C:\\Windows",
            b"C:\\Program Files",
            b"/etc/passwd",
            b"/root/",
            b"HKEY_LOCAL_MACHINE",
            b"registry",
            b"winreg"
        ],
        
        # Exfiltración de datos
        "data_theft": [
            b"socket",
            b"urllib.request.urlopen",
            b"requests.post",
            b"send(",
            b"upload(",
            b"credentials",
            b"password ="
        ],
        
        # Cifrado/Ofuscación (señal de ransomware)
        "encryption": [
            b"AES",
            b"RSA",
            b"encrypt",
            b"cipher",
            b"crypto",
            b".encrypted",
            b".locked"
        ],
        
        # Persistencia (permanece en el sistema)
        "persistence": [
            b"startup",
            b"scheduled task",
            b"cron",
            b"@reboot",
            b"autorun",
            b"registry.SetValueEx",
            b"WMI"
        ],
        
        # Descarga de código malicioso
        "malware_download": [
            b"http://",
            b"https://",
            b"urlopen",
            b"download",
            b".exe",
            b".dll",
            b".bat",
            b".ps1",
            b".scr",
            b".vbs"
        ],
        
        # Obfuscación del código
        "obfuscation": [
            b"base64",
            b"binascii",
            b"\\x",
            b"\\u",
            b"chr(",
            b"ord(",
            b"decode(",
            b"\\\\x"
        ]
    }
    
    @classmethod
    def is_known_malware(cls, md5_hash: str) -> bool:
        """
        Verifica si un hash es conocido como malware
        
        Args:
            md5_hash: Hash MD5 del archivo
            
        Returns:
            True si es malware conocido, False en caso contrario
        """
        return md5_hash.lower() in cls.MALWARE_SIGNATURES
    
    @classmethod
    def get_malware_name(cls, md5_hash: str) -> str:
        """
        Obtiene el nombre del malware si es conocido
        
        Args:
            md5_hash: Hash MD5 del archivo
            
        Returns:
            Nombre del malware o None
        """
        return cls.MALWARE_SIGNATURES.get(md5_hash.lower())
    
    @classmethod
    def is_dangerous_extension(cls, filepath: str) -> bool:
        """
        Verifica si la extensión es peligrosa
        
        Args:
            filepath: Ruta del archivo
            
        Returns:
            True si la extensión es peligrosa
        """
        import os
        _, ext = os.path.splitext(filepath.lower())
        return ext in cls.DANGEROUS_EXTENSIONS
    
    @classmethod
    def has_suspicious_patterns(cls, file_bytes: bytes) -> bool:
        """
        Verifica si el archivo contiene patrones sospechosos
        
        Args:
            file_bytes: Contenido del archivo
            
        Returns:
            True si contiene patrones sospechosos
        """
        for pattern in cls.SUSPICIOUS_PATTERNS:
            if pattern in file_bytes:
                return True
        return False
    
    @classmethod
    def analyze_malicious_code(cls, file_content: str) -> Dict[str, list]:
        """
        Analiza código en busca de comportamientos maliciosos
        
        Args:
            file_content: Contenido del archivo como string
            
        Returns:
            Diccionario con amenazas encontradas por categoría
        """
        threats_found = {}
        
        for category, patterns in cls.MALICIOUS_PATTERNS.items():
            found_patterns = []
            
            for pattern in patterns:
                # Convertir pattern a string para búsqueda en código
                try:
                    pattern_str = pattern.decode('utf-8', errors='ignore')
                except:
                    pattern_str = str(pattern)
                
                # Buscar en el contenido
                if pattern_str.lower() in file_content.lower():
                    found_patterns.append(pattern_str)
            
            if found_patterns:
                threats_found[category] = list(set(found_patterns))  # Eliminar duplicados
        
        return threats_found
    
    @classmethod
    def get_threat_description(cls, category: str) -> str:
        """
        Obtiene descripción amigable para cada categoría de amenaza
        """
        descriptions = {
            "command_execution": "⚠️ EJECUCIÓN DE COMANDOS: Intenta ejecutar comandos del sistema",
            "system_access": "🔓 ACCESO AL SISTEMA: Intenta acceder a archivos/registros del sistema",
            "data_theft": "💾 ROBO DE DATOS: Intenta enviar/robar información",
            "encryption": "🔐 CIFRADO: Patrón de ransomware o cifrado de datos",
            "persistence": "🔄 PERSISTENCIA: Intenta mantenerse en el sistema",
            "malware_download": "📥 DESCARGA DE MALWARE: Intenta descargar código malicioso",
            "obfuscation": "🪄 OFUSCACIÓN: Código oculto/cifrado - probable malware"
        }
        return descriptions.get(category, category)


class SignatureUpdater:
    """Gestiona actualizaciones de firmas de malware"""
    
    SIGNATURE_URL = "https://raw.githubusercontent.com/malware-database/signatures/main/patterns.json"
    LOCAL_SIGNATURES_FILE = "local_signatures.json"
    
    @classmethod
    def update_signatures(cls) -> bool:
        """
        Descarga y actualiza firmas de malware
        
        Returns:
            True si se actualizó correctamente
        """
        try:
            import requests
            import json
            
            print("\n📥 Descargando firmas actualizadas...")
            response = requests.get(cls.SIGNATURE_URL, timeout=10)
            
            if response.status_code == 200:
                signatures = response.json()
                
                # Guardar localmente
                with open(cls.LOCAL_SIGNATURES_FILE, 'w') as f:
                    json.dump(signatures, f, indent=2)
                
                print("✓ Firmas actualizadas correctamente")
                print(f"  {len(signatures.get('malware', {}))} firmas de malware cargadas")
                return True
            else:
                print(f"✗ Error al descargar: {response.status_code}")
                return False
        
        except Exception as e:
            print(f"✗ Error en actualización: {e}")
            return False
    
    @classmethod
    def load_custom_signatures(cls) -> Dict:
        """
        Carga firmas personalizadas locales
        
        Returns:
            Diccionario con firmas personalizadas
        """
        import json
        
        if not os.path.exists(cls.LOCAL_SIGNATURES_FILE):
            return {}
        
        try:
            with open(cls.LOCAL_SIGNATURES_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    @classmethod
    def add_custom_signature(cls, name: str, pattern: str, category: str):
        """
        Agrega una firma personalizada
        
        Args:
            name: Nombre de la firma
            pattern: Patrón a detectar
            category: Categoría de amenaza
        """
        import json
        
        signatures = cls.load_custom_signatures()
        
        if 'custom' not in signatures:
            signatures['custom'] = {}
        
        signatures['custom'][name] = {
            'pattern': pattern,
            'category': category,
            'added': datetime.now().isoformat()
        }
        
        with open(cls.LOCAL_SIGNATURES_FILE, 'w') as f:
            json.dump(signatures, f, indent=2)
        
        print(f"✓ Firma '{name}' agregada")
    
    @classmethod
    def get_update_info(cls) -> Dict:
        """
        Obtiene información sobre las firmas
        
        Returns:
            Información de firmas disponibles
        """
        import json
        from datetime import datetime
        
        info = {
            'built_in': len(MalwareDatabase.MALWARE_SIGNATURES),
            'categories': len(MalwareDatabase.MALICIOUS_PATTERNS),
            'patterns_total': sum(len(p) for p in MalwareDatabase.MALICIOUS_PATTERNS.values()),
            'last_update': None
        }
        
        if os.path.exists(cls.LOCAL_SIGNATURES_FILE):
            try:
                stat = os.stat(cls.LOCAL_SIGNATURES_FILE)
                info['last_update'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
                
                with open(cls.LOCAL_SIGNATURES_FILE, 'r') as f:
                    custom = json.load(f)
                    info['custom_signatures'] = len(custom.get('custom', {}))
            except:
                pass
        
        return info
    
    @classmethod
    def print_signature_stats(cls):
        """Imprime estadísticas de firmas"""
        info = cls.get_update_info()
        
        print("\n📋 ESTADÍSTICAS DE FIRMAS")
        print(f"   Firmas integradas: {info['built_in']}")
        print(f"   Categorías: {info['categories']}")
        print(f"   Patrones totales: {info['patterns_total']}")
        
        if info.get('custom_signatures'):
            print(f"   Firmas personalizadas: {info['custom_signatures']}")
        
        if info.get('last_update'):
            print(f"   Última actualización: {info['last_update']}")
        else:
            print(f"   Última actualización: Nunca (usar --update-signatures)")
