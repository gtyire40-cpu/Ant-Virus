#!/bin/bash
# SCRIPT DE DEMOSTRACIÓN - ESCÁNER DE ANTIVIRUS v1.0
# Este script ejecuta ejemplos de todas las características

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    DEMO: ESCÁNER DE ANTIVIRUS - TODOS LOS COMANDOS       ║"
echo "╚═══════════════════════════════════════════════════════════╝"

PYTHON="/home/markel/Descargas/ant virus/.venv/bin/python"
APP="/home/markel/Descargas/ant virus/antivirus.py"
BASE_DIR="/home/markel/Descargas/ant virus"

cd "$BASE_DIR"

# Esperar entre comandos
pause_demo() {
    echo ""
    echo "Presiona Enter para continuar..."
    read -r
}

# DEMO 1: Ver el menú de ayuda
echo ""
echo "📋 DEMO 1: MENÚ DE AYUDA (15 comandos disponibles)"
echo "═══════════════════════════════════════════════════════════"
$PYTHON antivirus.py --help
pause_demo

# DEMO 2: Ver estadísticas
echo ""
echo "📊 DEMO 2: ESTADÍSTICAS DEL SISTEMA"
echo "═══════════════════════════════════════════════════════════"
$PYTHON antivirus.py --stats
pause_demo

# DEMO 3: Ver historial
echo ""
echo "📋 DEMO 3: HISTORIAL DE ESCANEOS RECIENTES"
echo "═══════════════════════════════════════════════════════════"
$PYTHON antivirus.py --history
pause_demo

# DEMO 4: Listar cuarentena
echo ""
echo "🔒 DEMO 4: ARCHIVOS EN CUARENTENA"
echo "═══════════════════════════════════════════════════════════"
$PYTHON antivirus.py --list-quarantine
pause_demo

# DEMO 5: Escanear archivo
echo ""
echo "🔍 DEMO 5: ESCANEAR ARCHIVO INDIVIDUAL"
echo "═══════════════════════════════════════════════════════════"

# Crear un archivo de prueba con patrones maliciosos
TEST_FILE="demo_test.py"
cat > "$TEST_FILE" << 'PYTHON_EOF'
import os
import socket
# Este archivo simula malware con patrones detectables
os.system("whoami")  # Ejecución de comandos
s = socket.socket()  # Comunicación de red
s.connect(('C2.com', 9999))  # Conexión C2
PYTHON_EOF

$PYTHON antivirus.py "$TEST_FILE"
rm "$TEST_FILE"
pause_demo

# DEMO 6: Exportar a CSV
echo ""
echo "📊 DEMO 6: EXPORTAR HISTORIAL A CSV"
echo "═══════════════════════════════════════════════════════════"
CSV_FILE="demo_historial.csv"
$PYTHON antivirus.py --export-csv "$CSV_FILE"
echo ""
echo "Contenido del CSV:"
head -5 "$CSV_FILE"
echo "..."
rm "$CSV_FILE"
pause_demo

# DEMO 7: Ver firmas
echo ""
echo "🔧 DEMO 7: ESTADÍSTICAS DE FIRMAS DE MALWARE"
echo "═══════════════════════════════════════════════════════════"
$PYTHON -c "
from src.database import SignatureUpdater
SignatureUpdater.print_signature_stats()
"
pause_demo

# DEMO 8: Demostración de archivo comprimido
echo ""
echo "📦 DEMO 8: ESCANEAR ARCHIVO COMPRIMIDO"
echo "═══════════════════════════════════════════════════════════"

# Crear un ZIP de demostración
ZIP_TEST="demo_archive.zip"
python3 << PYTHON_EOF
import zipfile
with zipfile.ZipFile('$ZIP_TEST', 'w') as z:
    z.writestr('documento.txt', 'Contenido legítimo')
    z.writestr('virus.exe', 'Ejecutable')
    z.writestr('script.bat', 'Batch script')
print(f"✓ ZIP creado: $ZIP_TEST")
PYTHON_EOF

echo ""
$PYTHON antivirus.py "$ZIP_TEST"
rm "$ZIP_TEST"
pause_demo

# DEMO 9: Monitoreo en tiempo real (demostración corta)
echo ""
echo "👁️ DEMO 9: MONITOREO EN TIEMPO REAL (Demostración)"
echo "═══════════════════════════════════════════════════════════"
echo "Nota: Creando carpeta de demostración..."

DEMO_DIR="/tmp/antivirus_demo_watch"
mkdir -p "$DEMO_DIR"

echo ""
echo "Iniciando monitoreo en: $DEMO_DIR"
echo "(Se ejecutará durante 15 segundos)"
echo "En otra terminal, copia archivos a: $DEMO_DIR"
echo ""

timeout 15 $PYTHON -c "
from src.watcher import FileWatcher
watcher = FileWatcher('$DEMO_DIR')
watcher.start(interval=3, duration=15)
" 2>/dev/null &

WATCH_PID=$!
sleep 3

# Crear archivo de prueba mientras se monitorea
echo "🔔 Creando archivo de prueba..."
echo 'import os; os.system("ls")' > "$DEMO_DIR/test_file.py"

wait $WATCH_PID 2>/dev/null

rm -rf "$DEMO_DIR"
echo "✓ Demostración completada"
pause_demo

# DEMO 10: Verificar módulos de VirusTotal
echo ""
echo "🌍 DEMO 10: INTEGRACIÓN VIRUSTOTAL (Información)"
echo "═══════════════════════════════════════════════════════════"
$PYTHON -c "
from src.virustotal import VirusTotalScanner
print('Estado de VirusTotal:')
print(f'  Configurado: {VirusTotalScanner.is_configured()}')
print('')
if not VirusTotalScanner.is_configured():
    print('Para usar VirusTotal:')
    print('  1. Obtener API key en: https://www.virustotal.com/gui/home/upload')
    print('  2. Ejecutar: export VIRUSTOTAL_API_KEY=\"tu_clave_aqui\"')
    print('  3. Usar: python antivirus.py --virustotal archivo.exe')
"
pause_demo

# RESUMEN FINAL
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                   DEMOSTRACIÓN COMPLETADA                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "📊 RESUMEN DE FUNCIONALIDADES DEMOSTRADAS:"
echo "✓ 1. Menú de ayuda con 15 comandos"
echo "✓ 2. Estadísticas del sistema"
echo "✓ 3. Historial de escaneos"
echo "✓ 4. Gestión de cuarentena"
echo "✓ 5. Escaneo de archivos individuales"
echo "✓ 6. Exportación a CSV"
echo "✓ 7. Gestión de firmas malware"
echo "✓ 8. Análisis de archivos comprimidos"
echo "✓ 9. Monitoreo en tiempo real"
echo "✓ 10. Integración VirusTotal"
echo ""
echo "Para más información, ver:"
echo "  • CARACTERISTICAS_COMPLETAS.md"
echo "  • README.md"
echo "  • RESUMEN_FINAL.md"
echo ""
echo "¡Listo para usar! 🚀"
