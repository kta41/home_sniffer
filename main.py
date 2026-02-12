"""
# 📦 HOME_SNIFFER v1 - Professional Network Analyzer
# ---------------------------------------------------------
# ARQUITECTURA: Modular (MVC Simplified)
#   - core_sniffer.py: Motor de red asíncrono (Scapy).
#   - ui_app.py: Interfaz TUI (Textual).
#   - styles.css: Estilos visuales.
#
# SEGURIDAD (Auto-Privilegios):
#   - El sistema detecta si falta CAP_NET_RAW.
#   - Si es necesario, solicita sudo para configurar setcap y se auto-reinicia.
#   - Esto permite ejecución segura sin ser root directamente.
# ---------------------------------------------------------
"""

import os
import sys
import subprocess
from core_sniffer import SnifferEngine
from ui_app import HomeSnifferApp

def ensure_capabilities():
    """
    Verifica permisos de red. Si no los tiene, intenta configurar 
    capabilities en el binario de Python y relanza el proceso.
    """
    if sys.platform != "linux":
        return

    import socket
    try:
        # Intento de apertura de Raw Socket (Protocolo ETH_P_ALL)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.close()
    except PermissionError:
        if os.geteuid() != 0:
            print("\n[!] Permisos de red insuficientes.")
            print("[*] Configurando CAP_NET_RAW en el entorno virtual...")
            
            python_path = sys.executable
            # Intentamos instalar dependencias de sistema y asignar permisos
            cmd = f"sudo apt-get install -y libcap2-bin && sudo setcap 'cap_net_raw,cap_net_admin+eip' {python_path}"
            
            try:
                subprocess.run(cmd, shell=True, check=True)
                print("✅ Capabilities configuradas. Reiniciando aplicación...")
                # Relanzamos el proceso actual con los nuevos privilegios
                os.execv(python_path, [python_path] + sys.argv)
            except subprocess.CalledProcessError:
                print("❌ Error crítico: No se pudieron asignar permisos.")
                sys.exit(1)

def main():
    # 1. Asegurar privilegios antes de instanciar nada
    ensure_capabilities()

    # 2. Definir el callback de procesamiento
    def on_packet(pkt, info, payload):
        # Usamos la referencia de la app para inyectar datos en la UI
        app.handle_new_packet(pkt, info, payload)

    # 3. Inicializar componentes
    engine = SnifferEngine(packet_callback=on_packet)
    app = HomeSnifferApp(engine)

    # 4. Ejecutar TUI
    app.run()

if __name__ == "__main__":
    main()