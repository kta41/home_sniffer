from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static, Input
from textual.containers import Horizontal
from rich.text import Text
from scapy.all import wrpcap, Raw, IP, TCP, UDP
from datetime import datetime
from rich.markdown import Markdown
import re
import os

class HomeSnifferApp(App):
    CSS_PATH = "styles.css"
    
    BINDINGS = [
        ("s", "save_pcap", "Guardar PCAP"), 
        ("x", "clear", "Limpiar"),
        ("l", "release_cursor", "Reset/Seguir flujo"),
        ("ctrl+q", "quit", "Salir")
    ]

    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.all_data = [] 
        self.packet_history = {}
        self.search_filter = ""
        self.autoscroll_enabled = True

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(placeholder="[ BUSCAR... (IP, Puerto, Protocolo) ]", id="search-bar")
        with Horizontal():
            yield Static("SISTEMA DE ANÁLISIS\nESPERANDO TRÁFICO...", id="details")
            yield DataTable()
        yield Footer()

    def on_mount(self):
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("PROTO", "ORIGEN", "DESTINO", "PUERTO", "INFO")
        table.focus()
        self.engine.start()

    def handle_new_packet(self, pkt, info, payload):
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "IP"
        src, dst = pkt[IP].src, pkt[IP].dst
        port = str(pkt.sport) if (TCP in pkt or UDP in pkt) else "-"
        
        entry = (pkt, proto, src, dst, port, info, payload)
        self.all_data.insert(0, entry) # Siempre lo nuevo al índice 0
        
        if len(self.all_data) > 5000:
            self.all_data.pop()

        # Solo refrescamos la UI si el auto-scroll está encendido
        # Esto evita que el cursor "baile" cuando entran paquetes nuevos
        if self.autoscroll_enabled:
            self.call_from_thread(self.refresh_table_view)

    def refresh_table_view(self):
        table = self.query_one(DataTable)
        table.clear()
        self.packet_history.clear()

        count = 0
        search_query = self.search_filter.lower()

        for entry in self.all_data:
            pkt, proto, src, dst, port, info, payload = entry
            search_str = f"{proto} {src} {dst} {port} {info} {payload}".lower()
            
            if search_query in search_str:
                rk = table.add_row(proto, src, dst, port, Text.from_markup(info) if info else "")
                self.packet_history[rk] = pkt
                count += 1
            
            # Subimos el límite visual a 500 para mejorar las búsquedas
            if count >= 500: 
                break
        
        if self.autoscroll_enabled:
            table.scroll_to(y=0)

    def action_release_cursor(self):
        """Libera el bloqueo y vuelve al tiempo real."""
        self.autoscroll_enabled = True
        self.refresh_table_view()
        self.notify("Seguimiento reactivado")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Pausa el refresco visual y notifica SIEMPRE."""
        # Notificación persistente cada vez que seleccionas
        self.notify("Seguimiento pausado (Investigando)", severity="warning")
            
        self.autoscroll_enabled = False
        pkt = self.packet_history.get(event.row_key)
        
        if pkt:
            raw_struct = pkt.show(dump=True)
            # Limpiamos el formato para el panel de detalles
            pretty_struct = re.sub(r"###\[ (\w+) \]###", r"\n\n## \1\n---", raw_struct)
            md_text = f"# 📦 ANÁLISIS DE PAQUETE\n**Resumen:** `{pkt.summary()}`\n\n{pretty_struct}"
            self.query_one("#details", Static).update(Markdown(md_text))

    def on_input_changed(self, event: Input.Changed) -> None:
        self.search_filter = event.value
        # Al buscar, reactivamos el flujo para ver los resultados entrar
        self.autoscroll_enabled = True 
        self.refresh_table_view()
        
    def action_save_pcap(self):
        if self.engine.captured_raw:
            pcap_dir = "./pcaps"
            if not os.path.exists(pcap_dir): os.makedirs(pcap_dir)
            filename = f"cap_{datetime.now().strftime('%H%M%S')}.pcap"
            filepath = os.path.join(pcap_dir, filename)
            try:
                wrpcap(filepath, self.engine.captured_raw)
                self.notify(f"Guardado en {filepath}")
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")

    def action_clear(self):
        self.all_data.clear()
        self.packet_history.clear()
        self.engine.captured_raw.clear()
        self.query_one(DataTable).clear()