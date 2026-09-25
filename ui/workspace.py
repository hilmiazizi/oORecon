from __future__ import annotations

import asyncio

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, RichLog, Static, TabbedContent, TabPane
from textual.worker import Worker, WorkerState

from tools import brute_dirs, find_sitemaps, mine_js
from models import DirHit, HostCache, HostWorkspaceData, JsHit, PortHit, SitemapHit

LOG_MAX_LINES = 800
LOG_INTERVAL = 0.08
JS_LINK_KINDS = frozenset({"script", "endpoint", "url"})


class PortDetail(ModalScreen[None]):
	"""Detail window for a single open port."""

	BINDINGS = [
		Binding("escape", "dismiss", "Close", priority=True),
		Binding("enter", "dismiss", "Close", show=False),
	]

	CSS = """
	PortDetail {
		align: center middle;
	}
	#port-dialog {
		width: 72;
		height: auto;
		max-height: 80%;
		background: $surface;
		border: tall $accent;
		padding: 1 2;
	}
	#port-title {
		text-style: bold;
		color: $accent;
	}
	#port-subtitle {
		text-style: bold;
		margin-bottom: 1;
	}
	#port-rule {
		color: $text-muted;
		margin-bottom: 1;
	}
	#port-body {
		height: auto;
		max-height: 20;
	}
	#port-close {
		width: 100%;
		margin-top: 1;
	}
	"""

	def __init__(self, hit: PortHit) -> None:
		super().__init__()
		self.hit = hit

	def compose(self) -> ComposeResult:
		hit = self.hit
		body = Text()
		rows = (
			("Host", hit.host),
			("Port", str(hit.port)),
			("State", hit.state),
			("Service", hit.service or "-"),
			("Summary", hit.banner or "(no banner)"),
		)
		for label, value in rows:
			body.append(label.ljust(10), style="bold")
			style = "bold cyan" if label in {"Host", "Port", "Service"} else ""
			body.append(value + "\n", style=style)
		body.append("\n")
		body.append("Banner\n", style="bold")
		body.append("─" * 48 + "\n", style="dim")
		raw = hit.raw_banner.strip("\0") if hit.raw_banner else ""
		if raw.strip():
			body.append(raw.replace("\r\n", "\n").replace("\r", "\n"))
		else:
			body.append("(empty)", style="dim")

		with Vertical(id="port-dialog"):
			yield Static("PORT", id="port-title")
			yield Static(hit.host + ":" + str(hit.port), id="port-subtitle")
			yield Static("─" * 48, id="port-rule")
			with ScrollableContainer(id="port-body"):
				yield Static(body)
			yield Button("Close", id="port-close", variant="primary")

	def on_button_pressed(self, event: Button.Pressed) -> None:
		if event.button.id == "port-close":
			self.dismiss()

	def action_dismiss(self) -> None:
		self.dismiss()


class SecretDetail(ModalScreen[None]):
	"""Detail window for a JS Miner secret / key finding."""

	BINDINGS = [
		Binding("escape", "dismiss", "Close", priority=True),
		Binding("enter", "dismiss", "Close", show=False),
	]

	CSS = """
	SecretDetail {
		align: center middle;
	}
	#secret-dialog {
		width: 80;
		height: auto;
		max-height: 80%;
		background: $surface;
		border: tall $accent;
		padding: 1 2;
	}
	#secret-title {
		text-style: bold;
		color: $accent;
	}
	#secret-subtitle {
		text-style: bold;
		margin-bottom: 1;
	}
	#secret-rule {
		color: $text-muted;
		margin-bottom: 1;
	}
	#secret-body {
		height: auto;
		max-height: 24;
	}
	#secret-close {
		width: 100%;
		margin-top: 1;
	}
	"""

	def __init__(self, hit: JsHit) -> None:
		super().__init__()
		self.hit = hit

	def compose(self) -> ComposeResult:
		hit = self.hit
		body = Text()
		body.append("Kind".ljust(10), style="bold")
		body.append(hit.kind + "\n", style="bold cyan")
		body.append("Source".ljust(10), style="bold")
		body.append((hit.source or "-") + "\n")
		body.append("\n")
		body.append("Match\n", style="bold")
		body.append("─" * 56 + "\n", style="dim")
		body.append((hit.value or "(empty)") + "\n")
		body.append("\n")
		body.append("Context (± neighbors)\n", style="bold")
		body.append("─" * 56 + "\n", style="dim")
		if hit.context:
			body.append(hit.context)
		else:
			body.append("(no surrounding context)", style="dim")

		with Vertical(id="secret-dialog"):
			yield Static("SECRET", id="secret-title")
			yield Static(hit.kind, id="secret-subtitle")
			yield Static("─" * 56, id="secret-rule")
			with ScrollableContainer(id="secret-body"):
				yield Static(body)
			yield Button("Close", id="secret-close", variant="primary")

	def on_button_pressed(self, event: Button.Pressed) -> None:
		if event.button.id == "secret-close":
			self.dismiss()

	def action_dismiss(self) -> None:
		self.dismiss()


class DomainWorkspace(Screen):
	"""Per-host workspace with recon menus."""

	BINDINGS = [
		Binding("escape", "close", "Back", priority=True),
		Binding("ctrl+q", "app.quit", "Quit", priority=True),
		Binding("enter", "open_js_row", "Open", show=False),
	]

	CSS = """
	#ws-bar {
		height: 3;
		padding: 0 1;
	}
	#ws-host {
		width: 1fr;
		height: 3;
		content-align: left middle;
		text-style: bold;
	}
	#ws-status {
		width: auto;
		height: 3;
		content-align: right middle;
		color: $text-muted;
		padding-right: 1;
	}
	#ws-back {
		width: 12;
	}
	#ws-body {
		height: 1fr;
	}
	#ws-menu {
		height: 7fr;
	}
	#ws-menu Tabs {
		width: 100%;
		height: 4;
	}
	#ws-menu Tabs #tabs-list-bar,
	#ws-menu Tabs #tabs-list {
		width: 100%;
	}
	#ws-menu Tabs Tab {
		width: 1fr;
		height: 3;
		padding: 0 1;
		text-align: center;
		content-align: center middle;
		text-style: bold;
		color: $text-muted;
		background: $surface;
	}
	#ws-menu Tabs Tab:hover {
		color: $text;
		background: $foreground 10%;
	}
	#ws-menu Tabs Tab.-active {
		color: $text;
		background: $accent 25%;
		text-style: bold;
	}
	#ws-log-panel {
		height: 3fr;
		border-top: solid $accent;
		background: $surface;
	}
	#ws-log-title {
		height: 1;
		padding: 0 1;
		text-style: bold;
		color: $accent;
	}
	#ws-log {
		height: 1fr;
		padding: 0 1 0 1;
		scrollbar-size-vertical: 1;
	}
	TabPane {
		height: 1fr;
	}
	.tool-bar {
		height: 3;
		padding: 0 1;
	}
	.tool-hint {
		width: 1fr;
		height: 3;
		content-align: left middle;
		color: $text-muted;
	}
	.tool-run {
		width: 12;
	}
	.tool-stats {
		height: 1;
		padding: 0 1;
		color: $text-muted;
	}
	#dir-filters {
		height: 3;
		padding: 0 1;
	}
	#dir-filters Button {
		margin-right: 1;
		min-width: 8;
	}
	.tool-table {
		height: 1fr;
	}
	"""

	def __init__(self, host: str, cache: HostCache | None = None) -> None:
		super().__init__()
		self.host = host
		self._cache = cache if cache is not None else HostCache()
		self._worker: Worker | None = None
		self._tool = ""
		self._tool_status = {
			"sitemap": "",
			"directories": "",
			"jsminer": "",
		}
		self._log_at = 0.0
		self._sitemap_hits: list[SitemapHit] = []
		self._dir_hits: list[DirHit] = []
		self._js_hits: list[JsHit] = []
		self._dir_bucket = "all"

	def compose(self) -> ComposeResult:
		with Horizontal(id="ws-bar"):
			yield Static(self.host, id="ws-host")
			yield Static("", id="ws-status")
			yield Button("Back", id="ws-back")
		with Vertical(id="ws-body"):
			with TabbedContent(initial="sitemap", id="ws-menu"):
				with TabPane("Sitemap", id="sitemap"):
					with Horizontal(classes="tool-bar"):
						yield Static("robots.txt + sitemap wordlist", classes="tool-hint")
						yield Button("Run", id="run-sitemap", classes="tool-run", variant="primary")
					yield Static("Press Run", id="stats-sitemap", classes="tool-stats")
					yield DataTable(id="table-sitemap", classes="tool-table")
				with TabPane("Directories", id="directories"):
					with Horizontal(classes="tool-bar"):
						yield Static(
							"Directory bruteforce · SecLists common.txt (ffuf wordlist)",
							classes="tool-hint",
						)
						yield Button("Run", id="run-directories", classes="tool-run", variant="primary")
					yield Static("Press Run", id="stats-directories", classes="tool-stats")
					with Horizontal(id="dir-filters"):
						yield Button("All", id="df-all")
						yield Button("2xx", id="df-2")
						yield Button("3xx", id="df-3")
						yield Button("4xx", id="df-4")
						yield Button("5xx", id="df-5")
					yield DataTable(id="table-directories", classes="tool-table")
				with TabPane("JS Miner", id="jsminer"):
					with Horizontal(classes="tool-bar"):
						yield Static(
							"JS mine · main page + directory 200s",
							classes="tool-hint",
						)
						yield Button("Run", id="run-jsminer", classes="tool-run", variant="primary")
					yield Static("Press Run", id="stats-jsminer", classes="tool-stats")
					yield DataTable(id="table-jsminer", classes="tool-table")
			with Vertical(id="ws-log-panel"):
				yield Static("LOG", id="ws-log-title")
				yield RichLog(
					id="ws-log",
					max_lines=LOG_MAX_LINES,
					markup=True,
					highlight=False,
				)
		yield Footer()

	def on_mount(self) -> None:
		sitemap = self.query_one("#table-sitemap", DataTable)
		sitemap.add_column("Kind", width=10)
		sitemap.add_column("Detail", width=8)
		sitemap.add_column("URL")
		sitemap.cursor_type = "row"
		sitemap.zebra_stripes = True

		directories = self.query_one("#table-directories", DataTable)
		directories.add_column("Status", width=8)
		directories.add_column("Length", width=10)
		directories.add_column("URL")
		directories.cursor_type = "row"
		directories.zebra_stripes = True

		jsminer = self.query_one("#table-jsminer", DataTable)
		jsminer.add_column("Kind", width=22)
		jsminer.add_column("Value")
		jsminer.cursor_type = "row"
		jsminer.zebra_stripes = True

		self._set_dir_bucket("all")
		self._log("workspace " + self.host, "bold")
		cached = self._cache.get(self.host)
		if cached is not None and cached.complete:
			self._restore_cache(cached)
		else:
			self._start_all()

	def _restore_cache(self, data: HostWorkspaceData) -> None:
		self._sitemap_hits = list(data.sitemap)
		self._dir_hits = list(data.directories)
		self._js_hits = list(data.jsminer)
		self._tool_status = dict(data.stats)
		for tool, text in self._tool_status.items():
			if text:
				self.query_one("#stats-" + tool, Static).update(text)
		self._refresh_status()

		sitemap = self.query_one("#table-sitemap", DataTable)
		sitemap.clear()
		for hit in self._sitemap_hits:
			sitemap.add_row(hit.kind, hit.detail or "-", hit.url)

		self._rebuild_dir_table()

		jsminer = self.query_one("#table-jsminer", DataTable)
		jsminer.clear()
		for hit in self._js_hits:
			jsminer.add_row(hit.kind, hit.value)

		self._log("restored from memory cache", "cyan")
		self.query_one("#ws-status", Static).update("cached")

	def _save_cache(self, *, complete: bool | None = None) -> None:
		data = self._cache.ensure(self.host)
		data.sitemap = list(self._sitemap_hits)
		data.directories = list(self._dir_hits)
		data.jsminer = list(self._js_hits)
		data.stats = dict(self._tool_status)
		if complete is not None:
			data.complete = complete
		elif data.sitemap or data.directories or data.jsminer:
			# Keep complete True once a full pipeline finished.
			pass
		self._cache.put(data)

	def on_button_pressed(self, event: Button.Pressed) -> None:
		button_id = event.button.id or ""
		if button_id == "ws-back":
			self.action_close()
		elif button_id.startswith("df-"):
			self._set_dir_bucket(button_id[3:])
		elif button_id.startswith("run-"):
			self._run_tool(button_id[4:])

	def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
		if event.data_table.id == "table-jsminer":
			self._open_js_row(event.data_table, event.cursor_row)

	def action_open_js_row(self) -> None:
		if self.query_one(TabbedContent).active != "jsminer":
			return
		table = self.query_one("#table-jsminer", DataTable)
		self._open_js_row(table, table.cursor_row)

	def _open_js_row(self, table: DataTable, row: int | None) -> None:
		if row is None or row < 0 or table.row_count == 0:
			return
		if row >= len(self._js_hits):
			return
		hit = self._js_hits[row]
		if hit.kind in JS_LINK_KINDS:
			return
		self.app.push_screen(SecretDetail(hit))

	def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
		if event.worker is not self._worker or not self.is_running:
			return
		running = self._worker is not None and self._worker.is_running
		for tool in ("sitemap", "directories", "jsminer"):
			button = self.query_one("#run-" + tool, Button)
			if running and (self._tool == "all" or self._tool == tool):
				button.label = "Stop"
			else:
				button.label = "Run"
		if event.state == WorkerState.ERROR and event.worker.error is not None:
			self.notify(str(event.worker.error), severity="error", timeout=8)
			self._log(str(event.worker.error), "bold red")

	def action_close(self) -> None:
		if self._worker is not None and self._worker.is_running:
			self._worker.cancel()
		self._save_cache()
		self.app.pop_screen()

	def _log(self, message: str, style: str = "dim") -> None:
		if not self.is_running:
			return
		text = Text(message, style=style) if style else Text(message)
		self.query_one("#ws-log", RichLog).write(text)

	def _log_throttled(self, message: str, style: str = "dim") -> None:
		now = asyncio.get_running_loop().time()
		if now - self._log_at < LOG_INTERVAL:
			return
		self._log_at = now
		self._log(message, style)

	def _refresh_status(self) -> None:
		parts = [
			value
			for value in (
				self._tool_status["sitemap"],
				self._tool_status["directories"],
				self._tool_status["jsminer"],
			)
			if value
		]
		self.query_one("#ws-status", Static).update("   ·   ".join(parts))

	def _set_stats(self, tool: str, text: str) -> None:
		self.query_one("#stats-" + tool, Static).update(text)
		self._tool_status[tool] = text
		self._refresh_status()

	def _start_all(self) -> None:
		self._tool = "all"
		self._worker = self.run_worker(
			self._run_all(),
			name="workspace-all",
			group="workspace",
			exclusive=True,
			exit_on_error=False,
		)

	def _run_tool(self, tool: str) -> None:
		if self._worker is not None and self._worker.is_running:
			self._worker.cancel()
			self.query_one("#ws-status", Static).update("cancelled")
			self._log("cancelled", "yellow")
			return
		runners = {
			"sitemap": self._run_sitemap,
			"directories": self._run_directories,
			"jsminer": self._run_jsminer,
		}
		runner = runners.get(tool)
		if runner is None:
			return
		self._tool = tool
		self._worker = self.run_worker(
			runner(),
			name="workspace-" + tool,
			group="workspace",
			exclusive=True,
			exit_on_error=False,
		)

	async def _run_all(self) -> None:
		self._log("pipeline · sitemap → directories → jsminer(main+200s)", "cyan")
		steps = (
			("sitemap", self._run_sitemap),
			("directories", self._run_directories),
			("jsminer", self._run_jsminer),
		)
		for name, runner in steps:
			try:
				await runner()
			except asyncio.CancelledError:
				self._log("pipeline cancelled", "yellow")
				self._save_cache(complete=False)
				raise
			except Exception as exc:
				if self.is_running:
					self._log(name + " failed: " + str(exc), "bold red")
					self.notify(str(exc), severity="error", timeout=8)
		if self.is_running:
			self._save_cache(complete=True)
			self._log("workspace pipeline done", "cyan")

	async def _run_sitemap(self) -> None:
		table = self.query_one("#table-sitemap", DataTable)
		table.clear()
		self._sitemap_hits.clear()
		self._set_stats("sitemap", "fetching sitemap")
		self._log("sitemap · robots.txt + wordlist...")

		def on_progress(text: str) -> None:
			self._set_stats("sitemap", text)
			self._log_throttled("sitemap · " + text)

		def on_hit(hit: SitemapHit) -> None:
			self._sitemap_hits.append(hit)
			table.add_row(hit.kind, hit.detail or "-", hit.url)
			self._log("sitemap · " + hit.kind + " · " + hit.url, "cyan")

		try:
			hits = await find_sitemaps(self.host, on_progress=on_progress, on_hit=on_hit)
		except asyncio.CancelledError:
			self._set_stats("sitemap", "cancelled")
			self._log("sitemap cancelled", "yellow")
			self._save_cache(complete=False)
			raise
		except Exception as exc:
			self._set_stats("sitemap", "failed")
			self._log("sitemap failed: " + str(exc), "bold red")
			raise
		self._sitemap_hits = list(hits)
		self._set_stats("sitemap", str(len(hits)) + " entries")
		self._log("sitemap done · " + str(len(hits)) + " entries", "cyan")
		self._save_cache()

	def _set_dir_bucket(self, bucket: str) -> None:
		self._dir_bucket = bucket
		for name in ("all", "2", "3", "4", "5"):
			button = self.query_one("#df-" + name, Button)
			button.variant = "primary" if name == bucket else "default"
		self._rebuild_dir_table()

	def _dir_visible(self, hit: DirHit) -> bool:
		if hit.length <= 0:
			return False
		if self._dir_bucket == "all":
			return True
		code = str(hit.status)
		return bool(code) and code.startswith(self._dir_bucket)

	def _dir_row(self, hit: DirHit) -> None:
		table = self.query_one("#table-directories", DataTable)
		style = "bold green" if str(hit.status).startswith("2") else "yellow"
		if str(hit.status).startswith("3"):
			style = "cyan"
		elif str(hit.status).startswith("4"):
			style = "yellow"
		elif str(hit.status).startswith("5"):
			style = "bold magenta"
		table.add_row(Text(str(hit.status), style=style), str(hit.length), hit.url)

	def _rebuild_dir_table(self) -> None:
		table = self.query_one("#table-directories", DataTable)
		table.clear()
		for hit in self._dir_hits:
			if self._dir_visible(hit):
				self._dir_row(hit)

	async def _run_directories(self) -> None:
		table = self.query_one("#table-directories", DataTable)
		table.clear()
		self._dir_hits.clear()
		self._set_stats("directories", "bruteforcing " + self.host)
		self._log("dirs · bruteforcing " + self.host + "...")

		def on_progress(text: str) -> None:
			self._set_stats("directories", "dirs " + text)
			self._log_throttled("dirs · " + text)

		def on_hit(hit: DirHit) -> None:
			self._dir_hits.append(hit)
			if self._dir_visible(hit):
				self._dir_row(hit)
			self._log(
				"dirs · " + str(hit.status) + " · " + hit.url,
				"bold green" if str(hit.status).startswith("2") else "yellow",
			)

		try:
			hits = await brute_dirs(self.host, on_progress=on_progress, on_hit=on_hit)
		except asyncio.CancelledError:
			self._set_stats("directories", "cancelled")
			self._log("dirs cancelled", "yellow")
			self._save_cache(complete=False)
			raise
		except Exception as exc:
			self._set_stats("directories", "failed")
			self._log("dirs failed: " + str(exc), "bold red")
			raise
		self._set_stats("directories", str(len(hits)) + " hits")
		self._log("dirs done · " + str(len(hits)) + " hits", "cyan")
		self._save_cache()

	async def _run_jsminer(self) -> None:
		table = self.query_one("#table-jsminer", DataTable)
		table.clear()
		self._js_hits.clear()
		# Main page first, then every directory 200 URL.
		main = "https://" + self.host if "://" not in self.host else self.host.rstrip("/")
		targets = [main]
		for hit in self._dir_hits:
			if str(hit.status).startswith("2") and hit.url.rstrip("/") != main.rstrip("/"):
				targets.append(hit.url)
		self._set_stats("jsminer", "mining " + str(len(targets)) + " pages")
		self._log(
			"js · mining main + " + str(len(targets) - 1) + " directory 200s",
			"cyan",
		)

		def on_progress(text: str) -> None:
			self._set_stats("jsminer", text)
			self._log_throttled("js · " + text)

		def on_hit(hit: JsHit) -> None:
			self._js_hits.append(hit)
			table.add_row(hit.kind, hit.value)
			self._log("js · " + hit.kind + " · " + hit.value)

		try:
			hits = await mine_js(
				self.host,
				targets=targets,
				on_progress=on_progress,
				on_hit=on_hit,
			)
		except asyncio.CancelledError:
			self._set_stats("jsminer", "cancelled")
			self._log("js cancelled", "yellow")
			self._save_cache(complete=False)
			raise
		except Exception as exc:
			self._set_stats("jsminer", "failed")
			self._log("js failed: " + str(exc), "bold red")
			raise
		self._js_hits = list(hits)
		self._set_stats("jsminer", str(len(hits)) + " findings · enter on secrets")
		self._log("js done · " + str(len(hits)) + " findings", "cyan")
		self._save_cache()
