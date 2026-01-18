# Guía de Uso - Escáner de Antivirus

## Línea de Comandos

### Escanear un archivo:
```bash
python antivirus.py archivo.py
python antivirus.py ~/Descargas/descarga.exe
```

### Escanear una carpeta:
```bash
python antivirus.py ~/Documentos/
```

## Menú Interactivo

Ejecutar sin argumentos:
```bash
python antivirus.py
```

Se abrirá un menú con opciones para escanear archivos, carpetas, ver historial y estadísticas.

## Casos de Uso

### Verificar descarga sospechosa:
```bash
python antivirus.py ~/Descargas/archivo.exe
```

### Escanear carpeta de proyectos:
```bash
python antivirus.py ./proyectos/
```

### Monitorear descargas automáticamente:
```bash
python antivirus.py --watch-downloads
```

### Exportar resultados a CSV:
```bash
python antivirus.py --export-csv reporte.csv
```

## Comandos Disponibles

```bash
# Escaneo
python antivirus.py archivo.py
python antivirus.py carpeta/

# Historial y estadísticas
python antivirus.py --history
python antivirus.py --stats

# Cuarentena
python antivirus.py --quarantine archivo
python antivirus.py --list-quarantine
python antivirus.py --restore archivo

# Whitelist
python antivirus.py --trust archivo

# Reportes
python antivirus.py --export-csv reporte.csv

# Monitoreo
python antivirus.py --watch ~/carpeta
python antivirus.py --watch-downloads

# Otras opciones
python antivirus.py --update-signatures
python antivirus.py --virustotal archivo
python antivirus.py --help
```

## Interpretación de Resultados

Un archivo se marca como seguro cuando:
- No tiene extensión peligrosa
- Su hash no está en la base de datos de malware
- No contiene patrones maliciosos

Un archivo se marca como peligroso cuando:
- Tiene extensión sospechosa (.exe, .dll, .bat, etc.)
- Contiene patrones de código malicioso
- Intenta ejecución de comandos, robo de datos, persistencia, etc.

## Categorías de Amenaza

- Ejecución de comandos: Puede ejecutar código del sistema
- Acceso al sistema: Intenta acceder a archivos sensibles
- Robo de datos: Enviaría información a servidores remotos
- Cifrado: Ransomware que encripta archivos
- Persistencia: Se instalaría permanentemente
- Descarga de malware: Descargaría más virus
- Ofuscación: Código oculto

## Recomendaciones

Haz:
- Escanea todo antes de ejecutarlo
- Verifica descargas de fuentes desconocidas
- Revisa las amenazas detectadas

No hagas:
- Ejecutar archivos marcados como peligrosos
- Ignorar las advertencias
- Confiar en archivos de fuentes desconocidas
