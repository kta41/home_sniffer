import yaml
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, DNSQR
import threading
import os
import socket

class SnifferEngine:
    def __init__(self, packet_callback):
        self.packet_callback = packet_callback
        self.captured_raw = []
        self.rules = self._load_rules()
        
    def _load_rules(self):
        try:
            with open("rules.yaml", "r") as f:
                data = yaml.safe_load(f)
                if "critical_ports" in data and data["critical_ports"]:
                    data["critical_ports"] = {int(k): v for k, v in data["critical_ports"].items()}
                for key in ["excluded_ips", "excluded_domains", "excluded_ports", "signatures"]:
                    if key not in data or data[key] is None: data[key] = []
                return data
        except:
            return {"critical_ports": {}, "excluded_ips": [], "excluded_domains": [], "excluded_ports": [], "signatures": []}

    def reload_rules(self):
        self.rules = self._load_rules()
        return True

    def start(self):
        for iface in ["lo", "eth0", "wlan0"]:
            threading.Thread(target=self._run_sniff, args=(iface,), daemon=True).start()

    def _run_sniff(self, iface):
        try:
            sniff(iface=iface, prn=lambda pkt: self.process_packet(pkt, iface), store=False)
        except: pass

    def process_packet(self, pkt, iface):
        if not IP in pkt: return

        payload_str = ""
        if pkt.haslayer(Raw):
            payload_str = pkt[Raw].load.decode(errors="replace")

        # Filtros
        if pkt[IP].src in self.rules["excluded_ips"] or pkt[IP].dst in self.rules["excluded_ips"]: return
        if (TCP in pkt or UDP in pkt) and (pkt.sport in self.rules["excluded_ports"] or pkt.dport in self.rules["excluded_ports"]): return

        self.captured_raw.append(pkt)
        if len(self.captured_raw) > 5000: self.captured_raw.pop(0)

        info = ""
        # 1. Firmas de Payload
        payload_upper = payload_str.upper()
        for sig in self.rules["signatures"]:
            if sig["pattern"].upper() in payload_upper:
                info = f"[bold {sig['color']}]! {sig['label']}[/]"
                break

        # 2. Puertos Críticos
        if not info and (TCP in pkt or UDP in pkt):
            p_name = self.rules["critical_ports"].get(pkt.dport) or self.rules["critical_ports"].get(pkt.sport)
            if p_name: info = f"[bold magenta]! {p_name}[/]"

        # 3. DNS
        if not info and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors="replace")
            if any(dom in qname for dom in self.rules["excluded_domains"]): return
            info = f"[bold cyan]🔍 DNS:[/] {qname}"

        if not info: info = f"{pkt.summary()[:40]}..."
        info = f"[[blue]{iface}[/]] {info}"

        self.packet_callback(pkt, info, payload_str)