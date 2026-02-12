from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static, Input, Button
from textual.containers import Horizontal, VerticalScroll
from rich.text import Text
from rich.markdown import Markdown
from scapy.all import wrpcap, IP, TCP, UDP, DNS, DNSQR
from datetime import datetime
import re, os
from network_utils import get_ip_label


class HomeSnifferApp(App):

    CSS_PATH = "styles.css"

    BINDINGS = [
    ("ctrl+s", "save_pcap", "Guardar PCAP"),
    ("ctrl+x", "clear", "Limpiar"),
    ("ctrl+l", "release_cursor", "Seguir"),
    ("ctrl+r", "reload_config", "Recargar YAML"),
    ("ctrl+q", "quit", "Salir")
    ]


    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.all_data = []
        self.packet_history = {}
        self.search_filter = ""
        self.proto_filter = "ALL"
        self.autoscroll_enabled = True
        self.stats = {"TCP": 0, "UDP": 0, "ALERTAS": 0, "OTRO": 0, "ALL": 0}

    def compose(self) -> ComposeResult:
        yield Header()

        yield Input(placeholder="Buscar por IP, Puerto o Info...", id="search-bar")

        with Horizontal(id="filter-bar"):
            yield Button("ALL: 0", id="filter-all")
            yield Button("TCP: 0", id="filter-tcp")
            yield Button("UDP: 0", id="filter-udp")
            yield Button("ALERTAS: 0", id="filter-alertas")
            yield Button("OTROS: 0", id="filter-otros")

        with Horizontal(id="main-body"):
            with VerticalScroll(id="details-scroll"):
                yield Static(
                  "SELECCIONA UN PAQUETE PARA ANALIZAR",
                  id="details"
                )

            with VerticalScroll(id="table-scroll"):
                yield DataTable()



        yield Footer()

    def on_mount(self):
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("HORA", "PROTO", "ORIGEN", "DESTINO", "PUERTO", "INFO")
        table.focus()
        self.engine.start()

    def handle_new_packet(self, pkt, info, payload):
        timestamp = datetime.now().strftime("%H:%M:%S")

        if TCP in pkt:
            proto = "TCP"
        elif UDP in pkt:
            proto = "UDP"
        else:
            proto = "OTRO"

        src = get_ip_label(pkt[IP].src)
        dst = get_ip_label(pkt[IP].dst)
        port = str(pkt.sport) if (TCP in pkt or UDP in pkt) else "-"

        self.stats["ALL"] += 1
        if "!" in info:
            self.stats["ALERTAS"] += 1
        self.stats[proto] += 1

        entry = (timestamp, pkt, proto, src, dst, port, info, payload)
        self.all_data.insert(0, entry)

        if self.autoscroll_enabled:
            self.call_from_thread(self.refresh_table_view)
            self.call_from_thread(self.update_buttons_display)

    def update_buttons_display(self):
        self.query_one("#filter-all", Button).label = f"ALL: {self.stats['ALL']}"
        self.query_one("#filter-tcp", Button).label = f"TCP: {self.stats['TCP']}"
        self.query_one("#filter-udp", Button).label = f"UDP: {self.stats['UDP']}"
        self.query_one("#filter-alertas", Button).label = f"ALERTAS: {self.stats['ALERTAS']}"
        self.query_one("#filter-otros", Button).label = f"OTROS: {self.stats['OTRO']}"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        for btn in self.query(Button):
            btn.remove_class("active")

        event.button.add_class("active")

        button_id = event.button.id

        if button_id == "filter-all":
            self.proto_filter = "ALL"
        elif button_id == "filter-tcp":
            self.proto_filter = "TCP"
        elif button_id == "filter-udp":
            self.proto_filter = "UDP"
        elif button_id == "filter-alertas":
            self.proto_filter = "ALERTAS"
        elif button_id == "filter-otros":
            self.proto_filter = "OTRO"

        self.refresh_table_view()

    def refresh_table_view(self):
        table = self.query_one(DataTable)
        table.clear()
        self.packet_history.clear()

        count = 0
        search_query = self.search_filter.lower()

        for entry in self.all_data:
            time, pkt, proto, src, dst, port, info, payload = entry

            if self.proto_filter == "ALERTAS":
                if "!" not in info:
                    continue
            elif self.proto_filter != "ALL" and proto != self.proto_filter:
                continue

            search_str = f"{src} {dst} {info}".lower()
            if search_query not in search_str:
                continue

            rk = table.add_row(time, proto, src, dst, port, Text.from_markup(info))
            self.packet_history[rk] = {"pkt": pkt, "payload": payload}

            count += 1
            if count >= 100:
                break

        if self.autoscroll_enabled:
            table.scroll_to(y=0)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.autoscroll_enabled = False
        self.notify_limit("Escucha parada: modo análisis")
        data = self.packet_history.get(event.row_key)

        if data:
            pkt = data["pkt"]
            payload = data["payload"]

            scapy_dump = pkt.show(dump=True)    
            scapy_dump_fmt = re.sub(r"###\[ (.*) \]###", r"### \1", scapy_dump)

            md_content = [
                "# 📦 ANÁLISIS",
                f"**Resumen:** `{pkt.summary()}`"
            ]

            if pkt.haslayer(DNSQR):
                md_content.append(
                    f"> 🌐 **DNS:** `{pkt[DNSQR].qname.decode(errors='replace')}`"
                )

            md_content.append("## 🛠 ESTRUCTURA SCAPY")
            md_content.append(scapy_dump_fmt)

            md_content.append(
                f"## 📝 RAW\n```http\n{payload.strip() if payload else 'Sin datos'}\n```"
            )

            self.query_one("#details", Static).update(
                Markdown("\n\n".join(md_content))
            )

    def on_input_changed(self, event: Input.Changed) -> None:
        self.search_filter = event.value
        self.autoscroll_enabled = True
        self.refresh_table_view()

    def action_reload_config(self):
        if self.engine.reload_rules():
            self.notify_limit("Configuración Recargada")
            self.refresh_table_view()

    def action_clear(self):
        self.all_data.clear()
        self.packet_history.clear()
        self.engine.captured_raw.clear()
        self.notify_limit("Datos limpiados")
        self.query_one(DataTable).clear()

    def action_release_cursor(self):
        self.autoscroll_enabled = True
        self.refresh_table_view()
        self.notify_limit("Seguimiento reactivado")

    def action_save_pcap(self):
        if self.engine.captured_raw:
            pcap_dir = "./pcaps"
            if not os.path.exists(pcap_dir): os.makedirs(pcap_dir)
            filename = f"cap_{datetime.now().strftime('%H%M%S')}.pcap"
            filepath = os.path.join(pcap_dir, filename)
            try:
                wrpcap(filepath, self.engine.captured_raw)
                self.notify_limit(f"Guardado en {filepath}")
            except Exception as e:
                self.notify_limit(f"Error: {e}", severity="error")

    def action_quit(self) -> None:
        """Acción que se ejecuta al pulsar Ctrl+Q."""
        self.exit()


    def notify_limit(self, message: str, severity: str = "information", timeout: float = 1.0) -> None:
        # 1. Intentamos obtener las notificaciones del Screen actual
        try:
            # En Textual, las notificaciones están en 'self.screen._notifications' 
            # o se pueden sacar del ToastRack
            toasts = self.query("Toast") # Buscamos todos los widgets de tipo Toast (notificaciones)
            
            # 2. Si hay 3 o más widgets de notificación visibles
            if len(toasts) >= 3:
                # Borramos los que sobran (los más antiguos)
                for i in range(len(toasts) - 2): 
                    toasts[i].remove() # Eliminamos el widget directamente
        except Exception:
            pass # Si algo falla, que al menos salga la notificación

        # 3. Lanzamos la nueva
        self.notify(message, severity=severity, timeout=timeout)