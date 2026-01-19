# Ant-Virus
Un pequeño antivirus el cual puede funcionar en varios OS, apesar de no ser el mas avanzado puede llegar a hacer su trabajo. 

Para poder empezar deben:
1. Instalar el .zip y descromprimirlo. Luego descarguen las siguentes dependencias:

# LINUX/MAC
1. Navegar al proyecto
cd "/home/"su usuario"/Descargas/ant virus"

2. Eliminar entorno anterior (opcional)
rm -rf .venv

3. Crear entorno virtual
python3 -m venv .venv

4. Activar
source .venv/bin/activate

5. Instalar dependencias
pip install --upgrade pip
pip install -r requirements.txt

6. Verificar que funciona
python antivirus.py --help

# WINDOWS (powershell)
1. Navegar al proyecto
cd "C:\ruta\al\proyecto (pongan la ruta)

2. Eliminar entorno anterior (opcional)
Remove-Item -Recurse -Force .venv

3. Crear entorno virtual
python -m venv .venv

4. Activar
.venv\Scripts\Activate.ps1

5. Si da error de permisos, ejecuta:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

6. Instalar dependencias
python -m pip install --upgrade pip
pip install -r requirements.txt

7. Verificar que funciona
python antivirus.py --help


# WINDOWS (cdm)
1. Navegar al proyecto
cd C:\ruta\al\proyecto (pongan la ruta)

2. Eliminar entorno anterior (opcional)
rmdir /s /q .venv

3. Crear entorno virtual
python -m venv .venv

4. Activar
.venv\Scripts\activate.bat

5. Instalar dependencias
python -m pip install --upgrade pip
pip install -r requirements.txt

6. Verificar que funciona
python antivirus.py --help


# 3. Una vez echo, ya podran empezar

Y que pongo? Facil

ESCANEO
python antivirus.py archivo.py              # Escanear archivo

python antivirus.py ~/Documentos/           # Escanear carpeta


INFORMACIÓN
python antivirus.py --help                  # Ver ayuda completa

python antivirus.py --version               # Ver versión

python antivirus.py --stats                 # Ver estadísticas

python antivirus.py --history               # Ver últimos escaneos


GESTIÓN DE CUARENTENA
python antivirus.py --quarantine            # Ver archivos en cuarentena

python antivirus.py --restore archivo.py    # Restaurar de cuarentena


LISTA BLANCA
python antivirus.py --whitelist-add archivo.py      # Agregar archivo

python antivirus.py --whitelist-remove archivo.py   # Remover archivo


EXPORTAR
python antivirus.py --export-csv reporte.csv        # Exportar a CSV


MONITOREO
python antivirus.py --watch-downloads       # Monitorear descargas automáticamente

VIRUSTOTAL
python antivirus.py archivo.py --virustotal         # Análisis VirusTotal

FIRMAS
python antivirus.py --update-signatures     # Descargar firmas nuevas
