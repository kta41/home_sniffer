# 🛡️ Home_Sniffer v1.0

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-Packet_Analysis-blue?style=for-the-badge)](https://scapy.net/)
[![Textual](https://img.shields.io/badge/Textual-TUI_Framework-ff69b4?style=for-the-badge)](https://textual.textualize.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

**Home_Sniffer** es un analizador de tráfico de red en tiempo real diseñado para ejecutarse directamente en la terminal (TUI). Combina la potencia de inspección de paquetes de `Scapy` con una interfaz moderna y reactiva procesada en `Markdown`.

---

## 🚀 Tech Stack

| Componente | Tecnología | Uso |
| :--- | :--- | :--- |
| **Engine** | `Scapy` | Captura y disección de paquetes L2-L7. |
| **Interface** | `Textual` | Framework de TUI para una UI fluida y asíncrona. |
| **Rendering** | `Rich` | Renderizado de Markdown y tablas estilizadas en consola. |
| **Storage** | `PCAP` | Exportación de sesiones compatible con Wireshark. |

---

## ✨ Características Principales

* **🔍 Análisis Multinivel**: Inspección completa desde capas Ethernet hasta datos de aplicación (Raw).
* **📡 Escucha Dual**: Monitoriza interfaces locales (`lo`) y de red (`eth0/wlan0`) simultáneamente.
* **🚨 Sistema de Alertas**: Identificación visual de protocolos inseguros (HTTP) y puertos de administración (SSH, RDP).
* **📑 Vista Detallada**: Los paquetes seleccionados se desglosan en un panel lateral usando formato **Markdown** para mayor claridad.
* **💾 Persistencia**: Guarda capturas en caliente pulsando una sola tecla para análisis posterior.



---

## 🛠️ Instalación y Configuración

1. **Clona el repositorio:**
   
 ```bash
 git clone [https://github.com/kta41/Home_sniffer.git](https://github.com/kta41/Home_sniffer.git)
 cd Home_sniffer
 ```
2. Crea el entorno virtual e instala dependencias:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. Ejecución (Requiere privilegios de Root):
Para que el entorno virtual funcione correctamente con sudo:
```bash
sudo ./venv/bin/python main.py
```

## 🎮 Controles de la Interfaz

Tecla
Acción
* <kbd>ENTER</kbd>
Ver detalles técnicos del paquete seleccionado.
* <kbd>S</kbd>
Guardar captura actual en un archivo .pcap.
* <kbd>X</kbd>
Limpiar la tabla y liberar memoria.
* <kbd>Ctrl + Q</kbd>
Salir de la aplicación de forma segura.

---

Aviso de seguridad: Esta herramienta ha sido creada con fines educativos y de auditoría ética. El uso de sniffer en redes ajenas sin autorización es ilegal.




