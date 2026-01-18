# Escáner de Antivirus v1.0

Aplicación para escanear archivos y detectar contenido malicioso.

## Características

- Escaneo de archivos individuales
- Escaneo recursivo de carpetas
- Detección multimodal:
  - Análisis de firmas (base de datos de hashes)
  - Análisis de patrones sospechosos
  - Detección de extensiones peligrosas
- Interfaz de línea de comandos
- Historial de escaneos con SQLite
- Sistema de cuarentena
- Whitelist de archivos confiables

## Requisitos

- Python 3.9+
- pip
- requests
- python-magic

## Instalación

1. Clona o descarga este repositorio
2. Instala las dependencias:

```bash
pip install -r requirements.txt
```

## Uso

```bash
# Modo interactivo
python antivirus.py

# Escanear archivo
python antivirus.py archivo.py

# Escanear carpeta
python antivirus.py carpeta/

# Ver historial
python antivirus.py --history

# Ver estadísticas
python antivirus.py --stats

# Exportar a CSV
python antivirus.py --export-csv reporte.csv

# Monitoreo en tiempo real
python antivirus.py --watch-downloads
```

## Estructura del Proyecto

```
├── src/
│   ├── __init__.py           # Inicializador del paquete
│   ├── main.py               # Interfaz gráfica (tkinter)
│   ├── cli.py                # Interfaz de línea de comandos
│   ├── scanner.py            # Módulo principal de escaneo
│   ├── database.py           # Base de datos de firmas
│   └── utils.py              # Utilidades (análisis de archivos)
├── tests/
│   ├── __init__.py
│   └── test_scanner.py       # Suite de pruebas
├── antivirus.py              # Script de entrada CLI
├── run.py                    # Script de entrada principal
├── requirements.txt          # Dependencias
└── README.md                 # Este archivo
```

## Métodos de Detección

El escáner detecta 7 categorías de amenazas con 55+ patrones:
- Ejecución de comandos del sistema
- Acceso a archivos del sistema
- Robo de datos
- Cifrado/Ransomware
- Persistencia
- Descarga de malware
- Ofuscación de código

## Testing

Ejecuta la suite de pruebas:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

## Ejemplo de Uso

### Modo Interactivo

```
╔═══════════════════════════════════════════════════════════════╗
║                  ESCÁNER DE ANTIVIRUS v1.0.0                  ║
║              Detecta archivos maliciosos potenciales           ║
╚═══════════════════════════════════════════════════════════════╝

------------ OPCIONES: 
1. Escanear archivo
2. Escanear carpeta
3. Ver resumen
4. Salir

Selecciona una opción (1-4): 2
Ruta de la carpeta: /home/usuario/Descargas
⏳ Escaneando...

======================================================================
RESULTADO DEL ESCANEO
======================================================================

📁 Carpeta: /home/usuario/Descargas
   Archivos escaneados: 125
   Archivos seguros: 120
   Amenazas encontradas: 5
```

## Notas

- Este es un proyecto educativo y debe usarse con propósito legal
- La detección basada en firmas es limitada a la base de datos local
- Para detectar malware sofisticado, considera usar servicios en línea como VirusTotal

## Licencia

MIT