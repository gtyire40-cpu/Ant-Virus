"""
Interfaz gráfica para el escáner de antivirus
"""

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import threading
import os
from .scanner import AntivirusScanner


class AntivirusGUI:
    """Interfaz gráfica del antivirus"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Escáner de Antivirus")
        self.root.geometry("800x600")
        self.scanner = AntivirusScanner()
        self.is_scanning = False
        
        self._create_widgets()
        self._center_window()
    
    def _center_window(self):
        """Centra la ventana en la pantalla"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def _create_widgets(self):
        """Crea los widgets de la interfaz"""
        
        # Frame superior con botones
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X)
        
        # Botones
        ttk.Button(top_frame, text="Escanear Archivo", command=self.scan_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Escanear Carpeta", command=self.scan_directory).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Limpiar", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        
        # Frame de estado
        status_frame = ttk.LabelFrame(self.root, text="Estado del Escaneo", padding="10")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_var = tk.StringVar(value="Listo para escanear")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, foreground="blue")
        self.status_label.pack(fill=tk.X)
        
        # Barra de progreso
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)
        
        # Frame de resultados
        results_frame = ttk.LabelFrame(self.root, text="Resultados del Escaneo", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Área de texto con scroll
        self.results_text = scrolledtext.ScrolledText(
            results_frame, 
            height=20, 
            width=80,
            wrap=tk.WORD,
            font=("Courier", 9)
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Configurar colores para el texto
        self.results_text.tag_configure("safe", foreground="green")
        self.results_text.tag_configure("warning", foreground="orange")
        self.results_text.tag_configure("danger", foreground="red")
        self.results_text.tag_configure("info", foreground="blue")
    
    def scan_file(self):
        """Abre un diálogo para seleccionar un archivo"""
        filepath = filedialog.askopenfilename(
            title="Seleccionar archivo para escanear",
            initialdir=os.path.expanduser("~")
        )
        
        if filepath:
            self.perform_scan(filepath)
    
    def scan_directory(self):
        """Abre un diálogo para seleccionar una carpeta"""
        directory = filedialog.askdirectory(
            title="Seleccionar carpeta para escanear",
            initialdir=os.path.expanduser("~")
        )
        
        if directory:
            self.perform_scan(directory)
    
    def perform_scan(self, path):
        """Realiza el escaneo en un hilo separado"""
        if self.is_scanning:
            messagebox.showwarning("Advertencia", "Ya hay un escaneo en progreso")
            return
        
        self.is_scanning = True
        thread = threading.Thread(target=self._scan_thread, args=(path,))
        thread.daemon = True
        thread.start()
    
    def _scan_thread(self, path):
        """Hilo de escaneo"""
        try:
            self.root.after(0, lambda: self.progress.start())
            self.root.after(0, lambda: self.status_var.set(f"Escaneando: {os.path.basename(path)}..."))
            self.root.after(0, self.results_text.delete, "1.0", tk.END)
            
            # Realizar escaneo
            if os.path.isfile(path):
                result = self.scanner.scan_file(path)
                self.root.after(0, lambda: self._display_file_result(result))
            else:
                result = self.scanner.scan_directory(path)
                self.root.after(0, lambda: self._display_directory_result(result))
            
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.status_var.set("Escaneo completado"))
            self.root.after(0, self._set_scanning_false)
        
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Error durante el escaneo: {str(e)}"))
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.status_var.set("Error en el escaneo"))
            self.root.after(0, self._set_scanning_false)
    
    def _set_scanning_false(self):
        """Establece is_scanning a False"""
        self.is_scanning = False
    
    def _display_file_result(self, result):
        """Muestra resultados de un archivo"""
        self.results_text.insert(tk.END, "=" * 80 + "\n", "info")
        self.results_text.insert(tk.END, f"ESCANEO DE ARCHIVO\n", "info")
        self.results_text.insert(tk.END, "=" * 80 + "\n\n", "info")
        
        self.results_text.insert(tk.END, f"Archivo: {result.get('filename', 'N/A')}\n")
        self.results_text.insert(tk.END, f"Ruta: {result.get('filepath', 'N/A')}\n")
        self.results_text.insert(tk.END, f"Tamaño: {result.get('size', 'N/A')}\n")
        self.results_text.insert(tk.END, f"Tipo: {result.get('file_type', 'N/A')}\n")
        
        if result.get("error"):
            self.results_text.insert(tk.END, f"\n❌ Error: {result['error']}\n", "danger")
            return
        
        # Estado del archivo
        if result.get('is_safe'):
            self.results_text.insert(tk.END, f"\n✓ ARCHIVO SEGURO\n", "safe")
        else:
            self.results_text.insert(tk.END, f"\n✗ ARCHIVO POTENCIALMENTE PELIGROSO\n", "danger")
        
        # Amenazas detectadas
        if result.get('threats'):
            self.results_text.insert(tk.END, f"\nAmenazas detectadas ({len(result['threats'])}):\n", "warning")
            for threat in result['threats']:
                self.results_text.insert(tk.END, f"  • {threat['type']}: {threat['description']}\n", "warning")
        else:
            self.results_text.insert(tk.END, "\nNo se detectaron amenazas.\n", "safe")
        
        # Hashes
        if result.get('md5'):
            self.results_text.insert(tk.END, f"\nMD5: {result['md5']}\n")
        if result.get('sha256'):
            self.results_text.insert(tk.END, f"SHA256: {result['sha256']}\n")
    
    def _display_directory_result(self, result):
        """Muestra resultados de una carpeta"""
        self.results_text.insert(tk.END, "=" * 80 + "\n", "info")
        self.results_text.insert(tk.END, f"ESCANEO DE CARPETA\n", "info")
        self.results_text.insert(tk.END, "=" * 80 + "\n\n", "info")
        
        self.results_text.insert(tk.END, f"Carpeta: {result.get('directory', 'N/A')}\n")
        self.results_text.insert(tk.END, f"Archivos escaneados: {result.get('files_scanned', 0)}\n")
        self.results_text.insert(tk.END, f"Archivos seguros: {result.get('safe_files', 0)}\n", "safe")
        self.results_text.insert(tk.END, f"Amenazas encontradas: {result.get('threats_found', 0)}\n", "danger" if result.get('threats_found', 0) > 0 else "safe")
        
        if result.get('error'):
            self.results_text.insert(tk.END, f"\n⚠ Error: {result['error']}\n", "warning")
            return
        
        # Detalles de archivos con amenazas
        if result.get('threats_found', 0) > 0:
            self.results_text.insert(tk.END, "\n\nArchivos con amenazas:\n", "danger")
            for file_result in result.get('file_results', []):
                if not file_result.get('is_safe', True):
                    self.results_text.insert(tk.END, f"\n  ✗ {file_result.get('filename')}\n", "danger")
                    for threat in file_result.get('threats', []):
                        self.results_text.insert(tk.END, f"    - {threat['description']}\n", "warning")
    
    def clear_results(self):
        """Limpia los resultados"""
        self.results_text.delete("1.0", tk.END)
        self.status_var.set("Listo para escanear")
        self.scanner.clear_results()


def main():
    """Función principal"""
    root = tk.Tk()
    gui = AntivirusGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
