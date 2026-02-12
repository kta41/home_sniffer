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

import shlex  # Para manejar comandos de forma segura

def ensure_capabilities():
    if sys.platform != "linux":
        return

    import socket
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.close()
    except PermissionError:
        if os.geteuid() != 0:
            print("\n[!] Permisos insuficientes.")

            python_path = os.path.abspath(sys.executable)

            if "Home_sniffer" not in python_path:
                print("❌ Error: El binario de Python debe estar dentro del proyecto.")
                sys.exit(1)

            print(f"[*] Configurando CAP_NET_RAW en: {python_path}")

            cmds = [
                ["sudo", "apt-get", "install", "-y", "libcap2-bin"],
                ["sudo", "setcap", "cap_net_raw,cap_net_admin+eip", python_path]
            ]

            try:
                for cmd in cmds:
                    subprocess.run(cmd, check=True)

                print("✅ Hecho. Reiniciando...")
                os.execv(python_path, [python_path] + sys.argv)
            except Exception as e:
                print(f"❌ Error de seguridad o sistema: {e}")
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