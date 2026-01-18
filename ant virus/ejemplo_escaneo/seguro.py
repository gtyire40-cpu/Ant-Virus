"""
Script seguro - Sin código malicioso
"""

def hello_world():
    """Imprime un saludo"""
    print("¡Hola Mundo!")

def calculate_sum(a, b):
    """Suma dos números"""
    return a + b

def read_config_file():
    """Lee un archivo de configuración seguro"""
    with open('config.txt', 'r') as f:
        config = f.read()
    return config

if __name__ == "__main__":
    hello_world()
    result = calculate_sum(5, 3)
    print(f"Resultado: {result}")
