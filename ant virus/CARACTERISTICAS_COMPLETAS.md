# Características Completas

## Funcionalidades de Escaneo

### 1. Detección de Amenazas Signature-Based
- 7 categorías de amenazas
- Más de 55 patrones de detección
- Análisis de código ejecutable
- Validación de extensiones

### 2. Escaneo de Archivos Comprimidos
- Soporte para ZIP, TAR, GZ
- Análisis recursivo de contenido
- Extracción temporal segura
- Limpieza automática

### 3. Análisis de Archivos
- Detección de tipo MIME
- Validación de estructura
- Cálculo de hash SHA256
- Análisis de contenido binario

## Gestión de Amenazas

### Cuarentena
- Aislamiento de archivos detectados
- Directorio de almacenamiento seguro
- Metadatos de movimiento
- Restauración controlada

### Whitelist
- Exclusión de archivos seguros
- Persistencia en base de datos
- Configuración por usuario
- Gestión manual

### Historial
- Registro de todos los escaneos
- Timestamps precisos
- Amenazas detectadas
- Resultados de análisis

## Integración Externa

### VirusTotal
- Integración de API
- Búsqueda de amenazas conocidas
- Análisis adicional
- Verificación en la nube

### Actualizaciones de Firmas
- Descarga de nuevas definiciones
- Actualización automática
- Gestión de versiones
- Control de integridad

## Monitoreo en Tiempo Real

### File Watcher
- Monitoreo de directorios
- Escaneo automático
- Alertas en tiempo real
- Registro de eventos

### Monitoreo de Descargas
- Seguimiento de carpeta de descargas
- Escaneo automático
- Alertas inmediatas
- Historial persistente

## Base de Datos

### Almacenamiento
- SQLite integrado
- Tablas: scans, whitelist
- Consultas optimizadas
- Respaldo de datos

### Estadísticas
- Tasa de detección
- Amenazas encontradas
- Historiales de escaneo
- Análisis de tendencias

## Interfaz de Línea de Comandos

### Argumentos Principales
- Archivo único: `python antivirus.py archivo.py`
- Directorio: `python antivirus.py /ruta/carpeta`
- Carpeta recursiva: `python antivirus.py /ruta/carpeta/*`

### Flags Disponibles
- `--history`: Ver últimos 10 escaneos
- `--stats`: Estadísticas de escaneo
- `--export-csv`: Exportar datos
- `--quarantine`: Gestionar cuarentena
- `--restore`: Restaurar archivo
- `--whitelist-add`: Agregar a whitelist
- `--whitelist-remove`: Remover de whitelist
- `--watch-downloads`: Monitoreo automático
- `--virustotal`: Análisis adicional
- `--update-signatures`: Descargar firmas

## Resultados de Escaneo

Cada escaneo retorna:
- Archivo escaneado
- Estado (seguro/infectado)
- Amenazas detectadas (si aplica)
- Hash del archivo
- Timestamp del escaneo
- Categoría de riesgo

## Rendimiento

- Escaneo rápido de archivos pequeños
- Soporte para archivos grandes
- Análisis eficiente de carpetas
- Bajo consumo de CPU en monitoreo
