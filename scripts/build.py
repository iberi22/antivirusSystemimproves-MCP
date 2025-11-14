import subprocess
import sys
from pathlib import Path

def main():
    """
    Script de compilación para la aplicación MCP Windows Admin.

    Este script realiza los siguientes pasos:
    1. Instala las dependencias de desarrollo, incluyendo PyInstaller.
    2. Compila la extensión de Rust.
    3. Ejecuta PyInstaller para crear un ejecutable autocontenido.
    """
    print(">>> Paso 1: Instalando dependencias y compilando la extensión de Rust...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-e", ".[dev]"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error al instalar dependencias: {e}")
        sys.exit(1)

    print("\n>>> Paso 2: Ejecutando PyInstaller...")

    # El punto de entrada de la aplicación es `mcp_win_admin/server.py`
    entry_point = str(Path("mcp_win_admin") / "server.py")

    # Nombre del ejecutable de salida
    app_name = "mcp-win-admin"

    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "PyInstaller",
                entry_point,
                "--name",
                app_name,
                "--onefile",
                "--clean",
            ],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar PyInstaller: {e}")
        sys.exit(1)

    print(f"\n>>> Compilación completada. El ejecutable se encuentra en: dist/{app_name}")

if __name__ == "__main__":
    main()
