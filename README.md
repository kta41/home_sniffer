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

⚠️ Nota de Uso: Al seleccionar un paquete con el cursor, recibirás una notificación de "Seguimiento pausado". Esto es normal y permite analizar los datos sin que la tabla se desplace. Pulsa L para volver al flujo en vivo.

## 🎮 Controles de la Interfaz

| Tecla | Acción |
| :--- | :--- |
| <kbd>ENTER</kbd> | **Seleccionar**: Pausa el flujo y desglosa el paquete en el panel lateral. |
| <kbd>CTRL+L</kbd> | **Liberar**: Reactiva el seguimiento automático y salta al paquete más nuevo. |
| <kbd>CTRL+S</kbd> | **Guardar**: Exporta los últimos 5000 paquetes a un archivo `.pcap`. |
| <kbd>CTRL+X</kbd> | **Limpiar**: Vacía la tabla, los logs de sesión y libera la memoria RAM. |
| <kbd>Ctrl+Q</kbd> | **Salir**: Cierra los hilos de captura y sale de forma segura. |

## ⚙️ Reglas de Alerta (rules.yaml)

El motor de análisis es totalmente personalizable mediante un archivo YAML. Puedes definir qué patrones de tráfico deben disparar una alerta visual en la interfaz. Lo mejor es que puedes editar este archivo y pulsar <kbd>CTRL+R</kbd> para aplicar los cambios sin detener la captura.

## 📊 Filtrado Dinámico
La interfaz incluye una barra de herramientas reactiva para gestionar grandes volúmenes de datos:
Filtros Rápidos: Botones para alternar entre tráfico TCP, UDP, OTROS o ver el histórico completo (ALL).
Aislamiento de Alertas: Un filtro dedicado para visualizar únicamente los paquetes que coinciden con las reglas del archivo YAML.
Contadores en Tiempo Real: Estadísticas instantáneas del tráfico capturado por cada protocolo.


---

Aviso de seguridad: Esta herramienta ha sido creada con fines educativos y de auditoría ética. El uso de sniffer en redes ajenas sin autorización es ilegal.




