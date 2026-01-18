#!/usr/bin/env python3
"""
Generador de reportes de escaneo
Escanea una carpeta y genera un reporte en HTML
"""

import os
import sys
from datetime import datetime
from src.scanner import AntivirusScanner


def generate_html_report(directory: str, output_file: str = None):
    """
    Escanea una carpeta y genera un reporte HTML
    
    Args:
        directory: Carpeta a escanear
        output_file: Archivo de salida (default: scan_report_FECHA.html)
    """
    
    if not os.path.isdir(directory):
        print(f"❌ Carpeta no encontrada: {directory}")
        return
    
    # Generar nombre del archivo
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"scan_report_{timestamp}.html"
    
    print(f"⏳ Escaneando carpeta: {directory}")
    
    # Escanear
    scanner = AntivirusScanner()
    result = scanner.scan_directory(directory)
    
    # Generar HTML
    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reporte de Escaneo de Antivirus</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0;
                font-size: 2.5em;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            }}
            .timestamp {{
                color: #e0e0e0;
                margin-top: 10px;
            }}
            .summary {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                padding: 30px;
                background: #f5f5f5;
            }}
            .stat-box {{
                background: white;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            }}
            .stat-number {{
                font-size: 2.5em;
                font-weight: bold;
                margin: 10px 0;
            }}
            .stat-label {{
                color: #666;
                font-size: 0.9em;
            }}
            .safe {{ color: #4caf50; }}
            .danger {{ color: #f44336; }}
            .warning {{ color: #ff9800; }}
            .info {{ color: #2196f3; }}
            
            .content {{
                padding: 30px;
            }}
            
            .section-title {{
                font-size: 1.5em;
                color: #333;
                margin-bottom: 20px;
                border-bottom: 3px solid #667eea;
                padding-bottom: 10px;
            }}
            
            .file-result {{
                background: #f9f9f9;
                border-left: 4px solid #ddd;
                padding: 15px;
                margin-bottom: 15px;
                border-radius: 4px;
            }}
            
            .file-result.safe {{
                border-left-color: #4caf50;
                background: #f1f8f6;
            }}
            
            .file-result.dangerous {{
                border-left-color: #f44336;
                background: #fef1f0;
            }}
            
            .file-name {{
                font-weight: bold;
                font-size: 1.1em;
                margin-bottom: 8px;
            }}
            
            .file-details {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 10px;
                font-size: 0.9em;
                color: #666;
                margin-bottom: 10px;
            }}
            
            .threat-list {{
                background: white;
                padding: 10px;
                border-radius: 4px;
                margin-top: 10px;
            }}
            
            .threat-item {{
                padding: 8px;
                margin: 5px 0;
                background: #fef1f0;
                border-left: 3px solid #f44336;
                border-radius: 2px;
                font-size: 0.9em;
            }}
            
            .threat-type {{
                font-weight: bold;
                color: #f44336;
            }}
            
            .footer {{
                background: #f5f5f5;
                padding: 20px;
                text-align: center;
                color: #999;
                border-top: 1px solid #ddd;
            }}
            
            @media print {{
                body {{ background: white; }}
                .container {{ box-shadow: none; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Reporte de Escaneo de Antivirus</h1>
                <div class="timestamp">
                    Generado: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}<br>
                    Carpeta: {directory}
                </div>
            </div>
            
            <div class="summary">
                <div class="stat-box">
                    <div class="stat-label">Archivos Escaneados</div>
                    <div class="stat-number">{result.get('files_scanned', 0)}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Archivos Seguros</div>
                    <div class="stat-number safe">{result.get('safe_files', 0)}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Amenazas Detectadas</div>
                    <div class="stat-number danger">{result.get('threats_found', 0)}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Tasa de Detección</div>
                    <div class="stat-number info">
                        {result.get('threats_found', 0) / max(result.get('files_scanned', 1), 1) * 100:.1f}%
                    </div>
                </div>
            </div>
            
            <div class="content">
    """
    
    # Archivos con amenazas
    dangerous_files = [f for f in result.get('file_results', []) if not f.get('is_safe', True)]
    
    if dangerous_files:
        html_content += '<div class="section-title">⚠️ Archivos Peligrosos</div>'
        for file_result in dangerous_files:
            html_content += f"""
            <div class="file-result dangerous">
                <div class="file-name">❌ {file_result.get('filename', 'N/A')}</div>
                <div class="file-details">
                    <div><strong>Tamaño:</strong> {file_result.get('size', 'N/A')}</div>
                    <div><strong>Tipo:</strong> {file_result.get('file_type', 'N/A')}</div>
                    <div><strong>Amenazas:</strong> {len(file_result.get('threats', []))}</div>
                </div>
                <div class="threat-list">
            """
            
            for threat in file_result.get('threats', []):
                html_content += f"""
                <div class="threat-item">
                    <span class="threat-type">{threat['type']}:</span><br>
                    {threat['description']}
                </div>
                """
            
            html_content += """
                </div>
            </div>
            """
    
    # Archivos seguros (opcional)
    safe_files = [f for f in result.get('file_results', []) if f.get('is_safe', False)]
    
    if safe_files and len(safe_files) < 50:  # Solo mostrar si hay menos de 50
        html_content += '<div class="section-title">✓ Archivos Seguros</div>'
        for file_result in safe_files[:10]:  # Mostrar solo los primeros 10
            html_content += f"""
            <div class="file-result safe">
                <div class="file-name">✓ {file_result.get('filename', 'N/A')}</div>
                <div class="file-details">
                    <div><strong>Tamaño:</strong> {file_result.get('size', 'N/A')}</div>
                    <div><strong>Tipo:</strong> {file_result.get('file_type', 'N/A')}</div>
                </div>
            </div>
            """
        
        if len(safe_files) > 10:
            html_content += f'<p style="text-align: center; color: #999;">+ {len(safe_files) - 10} archivos más</p>'
    
    html_content += """
            </div>
            
            <div class="footer">
                <p>Generado automáticamente por Escáner de Antivirus v1.0.0</p>
                <p style="font-size: 0.8em;">Este reporte contiene información sensible sobre vulnerabilidades. Guárdalo en lugar seguro.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Guardar archivo
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ Reporte generado: {output_file}")
    print(f"\n📊 RESUMEN:")
    print(f"   Archivos escaneados: {result.get('files_scanned', 0)}")
    print(f"   Archivos seguros: {result.get('safe_files', 0)}")
    print(f"   Amenazas encontradas: {result.get('threats_found', 0)}")
    
    return output_file


if __name__ == "__main__":
    if len(sys.argv) > 1:
        directory = sys.argv[1]
        output = sys.argv[2] if len(sys.argv) > 2 else None
        generate_html_report(directory, output)
    else:
        print("Uso: python generate_report.py <carpeta> [archivo_salida.html]")
        print("\nEjemplo:")
        print("  python generate_report.py ~/Descargas")
        print("  python generate_report.py /home/usuario/Documentos reporte_custom.html")
