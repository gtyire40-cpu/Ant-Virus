"""
Tests para el módulo de scanner
"""

import unittest
import os
import tempfile
from src.scanner import AntivirusScanner
from src.database import MalwareDatabase
from src.utils import FileAnalyzer


class TestFileAnalyzer(unittest.TestCase):
    """Tests para FileAnalyzer"""
    
    def setUp(self):
        """Configura el ambiente de test"""
        self.analyzer = FileAnalyzer()
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.write(b"test content")
        self.temp_file.close()
    
    def tearDown(self):
        """Limpia después de los tests"""
        os.unlink(self.temp_file.name)
    
    def test_get_file_hash(self):
        """Prueba la función de hash"""
        hash_value = self.analyzer.get_file_hash(self.temp_file.name, "md5")
        self.assertIsNotNone(hash_value)
        self.assertEqual(len(hash_value), 32)  # MD5 tiene 32 caracteres
    
    def test_get_file_info(self):
        """Prueba obtención de información del archivo"""
        info = self.analyzer.get_file_info(self.temp_file.name)
        self.assertIn("name", info)
        self.assertIn("size", info)
        self.assertIn("md5", info)
    
    def test_suspicious_extension(self):
        """Prueba detección de extensión sospechosa"""
        is_suspicious, reason = self.analyzer.is_suspicious_extension("test.exe")
        self.assertTrue(is_suspicious)
        
        is_suspicious, reason = self.analyzer.is_suspicious_extension("test.txt")
        self.assertFalse(is_suspicious)


class TestMalwareDatabase(unittest.TestCase):
    """Tests para MalwareDatabase"""
    
    def test_is_known_malware(self):
        """Prueba detección de malware conocido"""
        # Usar un hash de la base de datos
        hash_malware = "5d41402abc4b2a76b9719d911017c592"
        self.assertTrue(MalwareDatabase.is_known_malware(hash_malware))
        
        # Usar un hash desconocido
        hash_unknown = "0000000000000000000000000000ffff"
        self.assertFalse(MalwareDatabase.is_known_malware(hash_unknown))
    
    def test_get_malware_name(self):
        """Prueba obtención del nombre del malware"""
        hash_malware = "5d41402abc4b2a76b9719d911017c592"
        name = MalwareDatabase.get_malware_name(hash_malware)
        self.assertIsNotNone(name)
    
    def test_dangerous_extension(self):
        """Prueba detección de extensión peligrosa"""
        self.assertTrue(MalwareDatabase.is_dangerous_extension("test.exe"))
        self.assertFalse(MalwareDatabase.is_dangerous_extension("test.pdf"))


class TestAntivirusScanner(unittest.TestCase):
    """Tests para AntivirusScanner"""
    
    def setUp(self):
        """Configura el ambiente de test"""
        self.scanner = AntivirusScanner()
        self.temp_dir = tempfile.mkdtemp()
        
        # Crear archivo de prueba
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "w") as f:
            f.write("This is a test file")
    
    def tearDown(self):
        """Limpia después de los tests"""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_scan_file(self):
        """Prueba escaneo de archivo"""
        result = self.scanner.scan_file(self.test_file)
        self.assertIn("filepath", result)
        self.assertIn("filename", result)
        self.assertIn("is_safe", result)
    
    def test_scan_nonexistent_file(self):
        """Prueba escaneo de archivo inexistente"""
        result = self.scanner.scan_file("/path/to/nonexistent/file")
        self.assertIn("status", result)
        self.assertEqual(result["status"], "error")
    
    def test_get_scan_summary(self):
        """Prueba resumen de escaneos"""
        self.scanner.scan_file(self.test_file)
        summary = self.scanner.get_scan_summary()
        
        self.assertIn("total_scans", summary)
        self.assertIn("safe_files", summary)
        self.assertIn("infected_files", summary)
        self.assertEqual(summary["total_scans"], 1)


if __name__ == "__main__":
    unittest.main()
