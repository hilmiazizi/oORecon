"""Main recon dashboard.

Lookup order (one phase at a time):
  1. DNS
  2. Reverse IP
  3. Leaked login URLs
  4. Ports
  5. Subdomains
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.widgets import (
	Button,
	DataTable,
	Footer,
	Input,
	ProgressBar,
	RichLog,
	Static,
	TabbedContent,
	TabPane,
)
from textual.worker import Worker, WorkerState

from models import HostCache, HostResult, LeakedUrlHit, PortHit, ReverseIpHit
from tools.ports import COMMON_PORTS
from ui.phases import DnsPhase, HostsPhase, LeakedPhase, PortsPhase, ReversePhase
from ui.styles import APP_CSS
from ui.workspace import DomainWorkspace, PortDetail
from utils import normalize_domain

BANNER = Text.from_ansi(Path(__file__).resolve().parents[1].joinpath("assets", "banner.ans").read_text(encoding="utf-8"))
LOG_MAX_LINES = 800
MISC_LOG_INTERVAL = 0.08


class ReconApp(App, DnsPhase, ReversePhase, LeakedPhase, PortsPhase, HostsPhase):
	"""Domain recon TUI. Phases live in ui.phases.*."""

	TITLE = "oORecon"
	CSS = APP_CSS
	BINDINGS = [
		Binding("ctrl+q", "quit", "Quit", priority=True),
		Binding("ctrl+c", "ignore", show=False, priority=True),
		Binding("escape", "back", "Back", show=False),
		Binding("a", "bucket('all')", "All", show=False),
		Binding("2", "bucket('2')", "2xx", show=False),
		Binding("3", "bucket('3')", "3xx", show=False),
		Binding("4", "bucket('4')", "4xx", show=False),
		Binding("5", "bucket('5')", "5xx", show=False),
		Binding("d", "bucket('down')", "Down", show=False),
		Binding("slash", "focus_filter", "Filter", show=False),
		Binding("enter", "open_row", "Open", show=False),
	]

	def __init__(self, domain: str = "") -> None:
		super().__init__()
		self.initial_domain = domain
		self.results: list[HostResult] = []
		self.total = 0
		self.bucket = "all"
		self.host_query = ""
		self._worker: Worker | None = None
		self._domain = ""
		self._dns_status = ""
		self._sub_status = ""
		self._port_status = ""
		self._port_hits: dict[str, PortHit] = {}
		self._port_log_at = 0.0
		self._host_log_at = 0.0
		self._host_ui_at = 0.0
		self._misc_log_at = 0.0
		self._pending_host_rows: list[HostResult] = []
		self._pending_host_logs: list[tuple[str, str]] = []
		self.host_cache = HostCache()
		self._dns_ips: list[str] = []
		self._reverse_hits: list[ReverseIpHit] = []
		self._rev_status = ""
		self._leaked_hits: list[LeakedUrlHit] = []
		self._leak_status = ""
		self._dns_done = asyncio.Event()
		self._sub_done = asyncio.Event()

	def compose(self) -> ComposeResult:
		with Vertical(id="home"):
			with Vertical(id="home-panel"):
				yield Static(BANNER, id="banner")
				yield Static("All in One Attack Surface Discovery Tool", id="tagline")
				with Vertical(id="form"):
					yield Input(placeholder="domain.com", id="domain")
					yield Button("Lookup", id="lookup", variant="primary")
					yield Static("", id="home-message")
				yield Static("enter  lookup     ctrl+q  quit", id="home-hint")
		with Vertical(id="results"):
			with Horizontal(id="result-bar"):
				yield Static("", id="result-domain")
				yield Static("", id="result-status")
				yield Button("Back", id="back")
			with Vertical(id="results-body"):
				with TabbedContent(initial="dns", id="menu"):
					with TabPane("DNS", id="dns"):
						yield Static("", id="dns-stats")
						with ScrollableContainer(id="dns-board"):
							yield Static("", id="dns-view")
					with TabPane("Subdomain", id="subdomain"):
						yield Static("", id="stats")
						yield ProgressBar(id="progress", total=1, show_eta=False)
						with Horizontal(id="filters"):
							yield Button("All", id="f-all")
							yield Button("2xx", id="f-2")
							yield Button("3xx", id="f-3")
							yield Button("4xx", id="f-4")
							yield Button("5xx", id="f-5")
							yield Button("Down", id="f-down")
							yield Input(placeholder="Filter hosts", id="host-filter")
						yield DataTable(id="table")
					with TabPane("Ports", id="ports"):
						yield Static("Shodan-style scan of the looked-up domain", id="stats-ports")
						yield ProgressBar(id="progress-ports", total=len(COMMON_PORTS), show_eta=False)
						yield DataTable(id="table-ports")
					with TabPane("Reverse IP", id="reverse"):
						yield Static("Hurricane Electric reverse IP / cert hostnames", id="stats-reverse")
						yield DataTable(id="table-reverse")
					with TabPane("Leaked Login URL", id="leaked"):
						yield Static("Hudson Rock leaked login / credential URLs", id="stats-leaked")
						yield DataTable(id="table-leaked")
				with Vertical(id="log-panel"):
					yield Static("LOG", id="log-title")
					yield RichLog(id="log", max_lines=LOG_MAX_LINES, markup=True, highlight=False)
		yield Footer()

	def on_mount(self) -> None:
		table = self.query_one("#table", DataTable)
		table.add_column("Status", width=8)
		table.add_column("Host")
		table.add_column("IP", width=18)
		table.add_column("Cloudflare", width=10)
		table.cursor_type = "row"
		table.zebra_stripes = True

		ports = self.query_one("#table-ports", DataTable)
		ports.add_column("Port", width=8)
		ports.add_column("Service", width=12)
		ports.add_column("Banner")
		ports.cursor_type = "row"
		ports.zebra_stripes = True
		self.query_one("#progress-ports", ProgressBar).update(total=len(COMMON_PORTS), progress=0)

		reverse = self.query_one("#table-reverse", DataTable)
		reverse.add_column("IP", width=18)
		reverse.add_column("Host")
		reverse.cursor_type = "row"
		reverse.zebra_stripes = True

		leaked = self.query_one("#table-leaked", DataTable)
		leaked.add_column("Type", width=10)
		leaked.add_column("Count", width=7)
		leaked.add_column("URL")
		leaked.cursor_type = None
		leaked.zebra_stripes = True

		self._set_bucket("all")
		self._show_home()
		if self.initial_domain:
			self.query_one("#domain", Input).value = self.initial_domain
		self.query_one("#domain", Input).focus()

	def on_button_pressed(self, event: Button.Pressed) -> None:
		button_id = event.button.id or ""
		if button_id == "lookup":
			self._lookup()
		elif button_id == "back":
			self._show_home()
		elif button_id.startswith("f-"):
			self._set_bucket(button_id[2:])

	def on_input_submitted(self, event: Input.Submitted) -> None:
		if event.input.id == "domain":
			self._lookup()

	def on_input_changed(self, event: Input.Changed) -> None:
		if event.input.id == "host-filter":
			self.host_query = event.value.strip().lower()
			self._rebuild_table()

	def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
		if not self.is_running:
			return
		if event.state == WorkerState.ERROR and event.worker.error is not None:
			self.notify(str(event.worker.error), severity="error", timeout=8)

	def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
		if event.pane.id == "subdomain":
			self._rebuild_table()

	def action_ignore(self) -> None:
		return

	def action_back(self) -> None:
		if self.query_one("#home").display:
			return
		self._show_home()

	def action_bucket(self, bucket: str) -> None:
		if self.query_one("#home").display:
			return
		if self.query_one(TabbedContent).active != "subdomain":
			return
		self._set_bucket(bucket)

	def action_focus_filter(self) -> None:
		if self.query_one("#home").display:
			return
		if self.query_one(TabbedContent).active != "subdomain":
			return
		self.query_one("#host-filter", Input).focus()

	def action_open_row(self) -> None:
		if self.query_one("#home").display:
			return
		active = self.query_one(TabbedContent).active
		if active == "subdomain":
			table = self.query_one("#table", DataTable)
			if table.row_count == 0:
				return
			row = table.cursor_row
			if row is None or row < 0:
				return
			try:
				host = str(table.get_row_at(row)[1])
			except Exception:
				return
			if host:
				self.push_screen(DomainWorkspace(host, cache=self.host_cache))
		elif active == "ports":
			self._open_port_row(self.query_one("#table-ports", DataTable))
		elif active == "reverse":
			table = self.query_one("#table-reverse", DataTable)
			if table.row_count == 0:
				return
			row = table.cursor_row
			if row is None or row < 0:
				return
			try:
				host = str(table.get_row_at(row)[1])
			except Exception:
				return
			if host:
				self.push_screen(DomainWorkspace(host, cache=self.host_cache))

	def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
		if event.data_table.id == "table":
			try:
				host = str(event.data_table.get_row_at(event.cursor_row)[1])
			except Exception:
				return
			if host:
				self.push_screen(DomainWorkspace(host, cache=self.host_cache))
		elif event.data_table.id == "table-ports":
			self._open_port_row(event.data_table, event)
		elif event.data_table.id == "table-reverse":
			try:
				host = str(event.data_table.get_row_at(event.cursor_row)[1])
			except Exception:
				return
			if host:
				self.push_screen(DomainWorkspace(host, cache=self.host_cache))

	def _open_port_row(
		self,
		table: DataTable,
		event: DataTable.RowSelected | None = None,
	) -> None:
		hit: PortHit | None = None
		if event is not None and event.row_key:
			hit = self._port_hits.get(str(event.row_key.value))
		if hit is None:
			row = event.cursor_row if event is not None else table.cursor_row
			if row is None or row < 0 or table.row_count == 0:
				return
			try:
				port = int(str(table.get_row_at(row)[0]))
			except Exception:
				return
			hit = self._port_hits.get(str(port))
		if hit is not None:
			self.push_screen(PortDetail(hit))

	def _show_home(self) -> None:
		self.query_one("#home").display = True
		self.query_one("#results").display = False
		self.query_one("#domain", Input).focus()

	def _show_results(self) -> None:
		self.query_one("#home").display = False
		self.query_one("#results").display = True

	def _domain_value(self) -> str:
		field = self.query_one("#domain", Input)
		domain = normalize_domain(field.value)
		if domain and domain != field.value.strip():
			field.value = domain
		return domain

	def _clear_log(self) -> None:
		self.query_one("#log", RichLog).clear()
		self._port_log_at = 0.0
		self._host_log_at = 0.0
		self._host_ui_at = 0.0
		self._misc_log_at = 0.0
		self._pending_host_rows = []
		self._pending_host_logs = []

	def _log(self, message: str, style: str = "dim") -> None:
		if not self.is_running:
			return
		text = Text(message, style=style) if style else Text(message)
		self.query_one("#log", RichLog).write(text)

	def _log_throttled(self, message: str, style: str = "dim") -> None:
		now = asyncio.get_running_loop().time()
		if now - self._misc_log_at < MISC_LOG_INTERVAL:
			return
		self._misc_log_at = now
		self._log(message, style)

	def _lookup(self) -> None:
		domain = self._domain_value()
		if not domain:
			self.query_one("#home-message", Static).update("Enter a domain")
			return
		self.query_one("#home-message", Static).update("")
		self.query_one("#result-domain", Static).update(domain)
		self._dns_status = "dns…"
		self._sub_status = "hosts…"
		self._port_status = "ports…"
		self._rev_status = "reverse…"
		self._leak_status = "leaked…"
		self._dns_ips = []
		self._reverse_hits = []
		self._leaked_hits = []
		self._dns_done = asyncio.Event()
		self._sub_done = asyncio.Event()
		self._clear_log()
		self._log("lookup " + domain, "bold")
		self._refresh_status()
		self._show_results()
		self.query_one("#table-reverse", DataTable).clear()
		self.query_one("#stats-reverse", Static).update("Waiting for DNS IPs…")
		self.query_one("#table-leaked", DataTable).clear()
		self.query_one("#stats-leaked", Static).update("Fetching leaked URLs…")
		self._worker = self.run_worker(
			self._run_lookup(domain),
			name="lookup",
			group="lookup",
			exclusive=True,
			exit_on_error=False,
		)

	async def _run_lookup(self, domain: str) -> None:
		# One phase at a time so the UI/log stay responsive under high
		# per-phase concurrency (dns → reverse → leaked → ports → hosts).
		for step in (
			self._run_dns(domain),
			self._run_reverse_ip(domain),
			self._run_leaked_urls(domain),
			self._run_ports(domain),
			self._run(domain),
		):
			try:
				await step
			except asyncio.CancelledError:
				raise
			except Exception as exc:
				if self.is_running:
					self.notify(str(exc), severity="error", timeout=8)

	def _refresh_status(self) -> None:
		if not self.is_running:
			return
		parts = [
			part
			for part in (
				self._dns_status,
				self._sub_status,
				self._port_status,
				self._rev_status,
				self._leak_status,
			)
			if part
		]
		self.query_one("#result-status", Static).update("   ·   ".join(parts))

