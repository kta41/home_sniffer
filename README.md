# 🛡️ Home_Sniffer v1.0

Analizador de protocolos de red ligero con interfaz **TUI** (Terminal User Interface) desarrollado en Python. Diseñado para entornos de auditoría rápida y monitoreo de tráfico en sistemas locales y contenedores.

## ✨ Características Principales

- **Arquitectura Modular**: Separación clara entre el motor de captura (`Scapy`) y la interfaz visual (`Textual`).
- **Visualización en Markdown**: Análisis detallado de paquetes con formato de títulos y bloques de código para máxima legibilidad.
- **Captura Dual**: Escucha simultánea en interfaces `lo` (loopback) y `eth0` (ethernet).
- **Detección Inteligente**:
  - Identificación de tráfico **HTTP inseguro** mediante firmas de verbos (GET, POST, etc.).
  - Monitorización de **puertos críticos** (SSH, Telnet, RDP).
  - Filtro automático de tráfico de control de **Kubernetes** (puertos 6443/6444).
- **Herramientas de Exportación**: Guardado de sesiones completas en formato estándar `.pcap`.

## 🛠️ Instalación

1. **Clonar el proyecto:**
   ```bash
   git clone [https://github.com/kta41/Home_sniffer.git](https://github.com/kta41/Home_sniffer.git)
   cd home_sniffer


Crear y activar entorno virtual:
Bash
python3 -m venv venv
source venv/bin/activate


Instalar dependencias:
Bash
pip install -r requirements.txt


🚦 Modo de Uso
Debido a que el análisis de paquetes requiere acceso a los sockets de red del kernel, el programa debe ejecutarse con privilegios de root.
Para usar el Python de tu entorno virtual con sudo, ejecuta:

Bash


sudo ./venv/bin/python main.py


Atajos de Teclado
S: Guardar la captura actual en un archivo .pcap.
X: Limpiar el historial de paquetes y vaciar la memoria RAM.
ENTER: Seleccionar un paquete en la tabla para ver el desglose de capas en el panel lateral.
📁 Estructura del Proyecto
main.py: Punto de entrada que orquesta el motor y la interfaz.
core_sniffer.py: Motor de red y lógica de detección de protocolos.
ui_app.py: Lógica de la interfaz de usuario y renderizado Markdown.
styles.css: Estilos visuales de la terminal (dialecto Textual CSS).
Desarrollado con fines educativos y de auditoría de red.



