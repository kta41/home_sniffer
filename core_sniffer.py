from scapy.all import sniff, IP, TCP, UDP, Raw
import threading
from datetime import datetime
import os

class SnifferEngine:
    def __init__(self, packet_callback, log_callback=None):
        self.packet_callback = packet_callback
        self.log_callback = log_callback
        self.captured_raw = []

        self.log_dir = "./logs"
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        # Generamos un nombre único para esta sesión
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(self.log_dir, f"log_{session_id}.log")

        # Encabezado del log de auditoría
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write(f"--- INICIO DE SESIÓN DE AUDITORÍA: {session_id} ---\n")

    def _write_to_audit_log(self, message):
        """Registra alertas técnicas en el archivo de log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")

    def start(self):
        """Inicia la captura asíncrona en interfaces locales y externas."""
        interfaces = ["lo", "eth0"]
        for iface in interfaces:
            thread = threading.Thread(
                target=self._run_sniff, 
                args=(iface,), 
                daemon=True # Cierra los hilos al salir de la app
            )
            thread.start()

    def _run_sniff(self, iface):
        """Ejecuta Scapy en segundo plano."""
        try:
            sniff(iface=iface, prn=self.process_packet, store=False)
        except Exception:
            pass

    def process_packet(self, pkt):
        """Analiza paquetes y gestiona la memoria de la sesión."""
        if IP in pkt:
            # 1. FILTRO INMEDIATO: Kubernetes (Evita procesar ruido innecesario)
            if TCP in pkt and (pkt.dport in [6443, 6444] or pkt.sport in [6443, 6444]):
                return
            
            # 2. GESTIÓN DE MEMORIA: Limitamos a 2000 paquetes para no saturar la RAM
            self.captured_raw.append(pkt)
            if len(self.captured_raw) > 2000:
                self.captured_raw.pop(0)

            info = ""
            payload_str = ""
            alert_detected = False
            extra_tech = f"| LEN: {len(pkt)}B"

            # 3. ANÁLISIS HTTP INSEGURO
            if pkt.haslayer(Raw):
                try:
                    raw_data = pkt[Raw].load
                    payload_str = raw_data.decode(errors="replace")
                    verbos = [b"GET ", b"POST ", b"HTTP/1", b"PUT ", b"DELETE "]
                    if any(v in raw_data for v in verbos):
                        if TCP in pkt and pkt.dport != 443 and pkt.sport != 443:
                            info = "[bold red]! HTTP INSEGURO[/]"
                            alert_detected = True
                except:
                    pass

            # 4. PUERTOS CRÍTICOS Y FLAGS TCP
            if TCP in pkt:
                extra_tech += f" | FLAGS: {pkt[TCP].flags}"
                critical_ports = {21: "FTP", 22: "SSH", 23: "TELNET", 445: "SMB", 3389: "RDP"}
                
                # Detectar si el puerto es crítico (destino u origen)
                p_critico = next((name for p, name in critical_ports.items() if p in [pkt.dport, pkt.sport]), None)
                if p_critico:
                    info = f"[bold magenta]! PUERTO CRÍTICO ({p_critico})[/]"
                    alert_detected = True

            # 5. REGISTRO EN LOG
            if alert_detected:
                clean_info = info.replace("[bold red]", "").replace("[bold magenta]", "").replace("[/]", "")
                puertos = f":{pkt.sport}->:{pkt.dport}" if TCP in pkt or UDP in pkt else ""
                log_entry = (
                    f"ORIGEN: {pkt[IP].src}{puertos} "
                    f"-> DESTINO: {pkt[IP].dst} "
                    f"| {clean_info} {extra_tech}"
                )
                self._write_to_audit_log(log_entry)

            # Notificar a la UI
            self.packet_callback(pkt, info, payload_str)