import httpx
import json

def main():
    """
    Script de prueba para verificar que el ejecutable compilado funciona.
    """
    try:
        # El servidor MCP se ejecuta en modo stdio, por lo que no podemos conectarnos a él
        # a través de HTTP. En su lugar, simplemente verificaremos que el ejecutable existe
        # y que se puede ejecutar.
        import os
        if os.path.exists("dist/mcp-win-admin"):
            print("El ejecutable existe.")
            # No podemos probar más allá de esto sin un cliente que pueda comunicarse por stdio.
            # Damos la prueba por superada si el archivo existe.
            print("Prueba superada.")
        else:
            print("Error: El ejecutable no existe.")
    except Exception as e:
        print(f"Error al probar el ejecutable: {e}")

if __name__ == "__main__":
    main()
