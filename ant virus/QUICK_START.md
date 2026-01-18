# Inicio Rápido

## Requisitos

- Python 3.9+
- pip instalado
- requests y python-magic

## Instalación Rápida

```bash
cd "/home/markel/Descargas/ant virus"
source .venv/bin/activate
pip install -r requirements.txt
```

## Primeros Pasos

```bash
# Ver ayuda
python antivirus.py --help

# Escanear archivo
python antivirus.py archivo.py

# Escanear carpeta
python antivirus.py ~/Documentos/

# Ver estadísticas
python antivirus.py --stats

# Monitorear descargas
python antivirus.py --watch-downloads
```

## Comandos Principales

| Comando | Descripción |
|---------|-------------|
| `python antivirus.py archivo` | Escanear archivo |
| `python antivirus.py carpeta/` | Escanear carpeta |
| `--history` | Ver últimos escaneos |
| `--stats` | Ver estadísticas |
| `--export-csv` | Exportar a CSV |
| `--quarantine` | Poner en cuarentena |
| `--restore` | Restaurar archivo |
| `--watch-downloads` | Monitorear descargas |
| `--virustotal` | Usar VirusTotal API |
| `--help` | Ver todos los comandos |

## Troubleshooting

### Error de módulos
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### Permiso denegado
```bash
chmod +x antivirus.py
chmod +x demo.sh
```

## Documentación

- README.md: Descripción general
- HOWTO.md: Guía de uso detallada
