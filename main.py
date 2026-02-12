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
    if sys.platform != "linux":
        return

    import socket
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.close()
    except PermissionError:
        if os.geteuid() != 0:
            print("\n[!] Permisos de red insuficientes.")

            python_path = sys.executable

            if os.path.islink(python_path):
                print("[*] Convirtiendo el binario del venv en un archivo real para asignar permisos...")
                real_bin = os.path.realpath(python_path)
                subprocess.run(f"sudo cp {real_bin} {python_path}", shell=True)

            print("[*] Configurando CAP_NET_RAW...")
            cmd = f"sudo setcap 'cap_net_raw,cap_net_admin+eip' {python_path}"

            try:
                subprocess.run(cmd, shell=True, check=True)
                print("✅ Permisos configurados. Reiniciando...")
                os.execv(python_path, [python_path] + sys.argv)
            except Exception as e:
                print(f"❌ Error: {e}")
                sys.exit(1)

def main():
    ensure_capabilities()

    def on_packet(pkt, info, payload):
        app.handle_new_packet(pkt, info, payload)

    engine = SnifferEngine(packet_callback=on_packet)
    app = HomeSnifferApp(engine)

    app.run()

if __name__ == "__main__":
    main()
