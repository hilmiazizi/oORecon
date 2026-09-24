"""Certificate-transparency subdomain probe phase."""

import asyncio

from textual.widgets import Button, DataTable, ProgressBar, Static, TabbedContent

from models import HostResult
from tools.certsub import CertSubError, certsub
from ui.format import cloudflare_text, status_text

HOST_LOG_INTERVAL = 0.08
HOST_UI_INTERVAL = 0.2


class HostsPhase:
	def _subdomain_visible(self) -> bool:
		return (
			not self.query_one("#home").display
			and self.query_one(TabbedContent).active == "subdomain"
		)

	async def _run(self, domain: str) -> None:
		self.results.clear()
		self._status_counts = {"2": 0, "3": 0, "4": 0, "5": 0, "down": 0}
		self.total = 0
		self._domain = domain
		self._rebuild_table()
		self.query_one("#progress", ProgressBar).update(total=1, progress=0)
		self._sub_status = "hosts…"
		self._refresh_status()
		self._set_stats("Fetching certificates for " + domain)
		self._log("fetching certificates for " + domain + "...")
		try:
			await certsub(
				domain,
				on_hosts=self._on_hosts,
				on_check=self._on_check,
				on_result=self._on_result,
			)
		except asyncio.CancelledError:
			self._sub_status = "hosts cancelled"
			self._refresh_status()
			self._set_stats("Cancelled " + domain)
			self._log("hosts cancelled", "yellow")
			raise
		except CertSubError as exc:
			self._sub_status = "hosts failed"
			self._refresh_status()
			self._set_stats(str(exc))
			self._log("hosts failed: " + str(exc), "bold red")
			if self.is_running:
				self.notify(str(exc), severity="error", timeout=8)
			return
		finally:
			self._sub_done.set()
		self._flush_host_rows(force=True)
		self._sub_status = "hosts " + str(len(self.results))
		self._refresh_status()
		self._set_stats("Done " + domain)
		self._log("hosts done · " + str(len(self.results)) + " checked", "cyan")

	def _flush_host_rows(self, *, force: bool = False) -> None:
		if not self._pending_host_rows:
			return
		if not self._subdomain_visible() and not force:
			self._pending_host_rows.clear()
			return
		table = self.query_one("#table", DataTable)
		follow = table.row_count == 0 or table.cursor_row >= table.row_count - 1
		for result in self._pending_host_rows:
			if not self._visible(result):
				continue
			table.add_row(
				status_text(result),
				result.host,
				result.ip or "-",
				cloudflare_text(result),
			)
		self._pending_host_rows.clear()
		if follow and table.row_count:
			table.move_cursor(row=table.row_count - 1)

	def _on_hosts(self, hosts: list[str]) -> None:
		if not self.is_running:
			return
		self.total = len(hosts)
		self._pending_host_rows.clear()
		self.query_one("#progress", ProgressBar).update(total=max(self.total, 1), progress=0)
		self._sub_status = "0/" + str(self.total)
		self._refresh_status()
		self._set_stats("Checking " + self._domain)
		self._log("found " + str(len(hosts)) + " certificate names", "cyan")

	def _on_check(self, host: str) -> None:
		if not self.is_running:
			return
		now = asyncio.get_running_loop().time()
		if now - self._host_log_at < HOST_LOG_INTERVAL:
			return
		self._host_log_at = now
		self._log("fetching " + host + "...")

	def _on_result(self, result: HostResult, done: int, total: int) -> None:
		if not self.is_running:
			return
		self.results.append(result)
		self._bump_count(result)
		self.total = total
		if self._subdomain_visible() and self._visible(result):
			self._pending_host_rows.append(result)
		now = asyncio.get_running_loop().time()
		refresh_ui = done >= total or now - self._host_ui_at >= HOST_UI_INTERVAL
		if refresh_ui:
			self._host_ui_at = now
			self._flush_host_rows(force=done >= total)
			self.query_one("#progress", ProgressBar).update(total=max(total, 1), progress=done)
			self._sub_status = str(done) + "/" + str(total)
			self._refresh_status()
			self._set_stats("Checking " + self._domain)
		status = result.status or "down"
		ip = result.ip or "-"
		cf = "cf:yes" if result.cloudflare else "cf:no"
		log_2xx = bool(result.status and result.status.startswith("2"))
		if now - self._host_log_at >= HOST_LOG_INTERVAL or log_2xx:
			self._host_log_at = now
			self._log(result.host + " · " + status + " · " + ip + " · " + cf)

	async def _run_ports(self, domain: str) -> None:
		if not self.is_running:
			return
		table = self.query_one("#table-ports", DataTable)
		progress = self.query_one("#progress-ports", ProgressBar)
		table.clear()
		self._port_hits.clear()
		self._port_log_at = 0.0
		total = len(COMMON_PORTS)
		progress.update(total=total, progress=0)
		self._port_status = "ports…"
		self._refresh_status()
		self.query_one("#stats-ports", Static).update(
			"Scanning " + domain + " · " + str(total) + " ports"
		)
		self._log("scanning " + str(total) + " ports on " + domain + "...")

		def on_progress(done: int, total_ports: int) -> None:
			if not self.is_running:
				return
			progress.update(total=total_ports, progress=done)
			self._port_status = "ports " + str(done) + "/" + str(total_ports)
			self._refresh_status()
			self.query_one("#stats-ports", Static).update(
				"Scanning " + domain + " · " + str(done) + "/" + str(total_ports)
			)

		def on_probe(port: int) -> None:
			if not self.is_running:
				return
			now = asyncio.get_running_loop().time()
			if now - self._port_log_at < PORT_LOG_INTERVAL:
				return
			self._port_log_at = now
			self._log("scanning port " + str(port) + "...")

		def on_hit(hit: PortHit) -> None:
			if not self.is_running:
				return
			key = str(hit.port)
			self._port_hits[key] = hit
			banner = hit.banner[:120] if hit.banner else Text("open", style="bold green")
			table.add_row(
				Text(str(hit.port), style="bold cyan"),
				hit.service or "-",
				banner,
				key=key,
			)
			detail = hit.service or hit.banner[:60] or "open"
			self._log("open port " + str(hit.port) + " · " + detail, "bold green")

		try:
			hits = await scan_ports(
				domain,
				on_progress=on_progress,
				on_probe=on_probe,
				on_hit=on_hit,
			)
		except asyncio.CancelledError:
			self._port_status = "ports cancelled"
			self._refresh_status()
			self._log("ports cancelled", "yellow")
			raise
		except Exception as exc:
			if self.is_running:
				self._port_status = "ports failed"
				self._refresh_status()
				self.query_one("#stats-ports", Static).update(str(exc))
				self._log("ports failed: " + str(exc), "bold red")
				self.notify(str(exc), severity="error", timeout=8)
			return
		if self.is_running:
			progress.update(total=total, progress=total)
			self._port_status = "ports " + str(len(hits))
			self._refresh_status()
			self.query_one("#stats-ports", Static).update(
				str(len(hits)) + " open on " + domain + " · enter for details"
			)
			self._log("ports done · " + str(len(hits)) + " open", "cyan")

	async def _run_leaked_urls(self, domain: str) -> None:
		if not self.is_running:
			return
		table = self.query_one("#table-leaked", DataTable)
		table.clear()
		self._leaked_hits.clear()
		self._leak_status = "leaked…"
		self._refresh_status()
		self.query_one("#stats-leaked", Static).update("Fetching leaked URLs for " + domain)
		self._log("leaked · fetching " + domain + "...")

		def on_progress(text: str) -> None:
			if not self.is_running:
				return
			self._leak_status = "leaked " + str(len(self._leaked_hits))
			self._refresh_status()
			self.query_one("#stats-leaked", Static).update(text)
			self._log_throttled("leaked · " + text)

		def on_hit(hit: LeakedUrlHit) -> None:
			if not self.is_running:
				return
			self._leaked_hits.append(hit)
			table.add_row(hit.kind, str(hit.occurrence), hit.url)
			self._log_throttled("leaked · " + hit.kind + " · " + hit.url)

		try:
			hits = await leaked_login_urls(
				domain,
				on_progress=on_progress,
				on_hit=on_hit,
			)
		except asyncio.CancelledError:
			self._leak_status = "leaked cancelled"
			self._refresh_status()
			self._log("leaked cancelled", "yellow")
			raise
		except LeakedUrlError as exc:
			self._leak_status = "leaked failed"
			self._refresh_status()
			self.query_one("#stats-leaked", Static).update(str(exc))
			self._log("leaked failed: " + str(exc), "bold red")
			self.notify(str(exc), severity="error", timeout=8)
			return

		if self.is_running:
			# Table may already have rows from on_hit; rebuild sorted.
			table.clear()
			self._leaked_hits = list(hits)
			for hit in hits:
				table.add_row(hit.kind, str(hit.occurrence), hit.url)
			self._leak_status = "leaked " + str(len(hits))
			self._refresh_status()
			self.query_one("#stats-leaked", Static).update(
				str(len(hits)) + " urls"
			)
			self._log("leaked done · " + str(len(hits)) + " urls", "cyan")

	def _visible(self, result: HostResult) -> bool:
		if self.bucket == "down":
			if result.status:
				return False
		elif self.bucket in "2345":
			if not result.status or not result.status.startswith(self.bucket):
				return False
		if self.host_query and not result.host.lower().startswith(self.host_query):
			return False
		return True

	def _bump_count(self, result: HostResult) -> None:
		counts = self._status_counts
		if not result.status:
			counts["down"] += 1
		elif result.status[0] in counts:
			counts[result.status[0]] += 1

	def _set_stats(self, prefix: str) -> None:
		if not self.is_running:
			return
		if self.total:
			counts = self._status_counts
			detail = (
				str(len(self.results)) + "/" + str(self.total)
				+ "   2xx " + str(counts["2"])
				+ "   3xx " + str(counts["3"])
				+ "   4xx " + str(counts["4"])
				+ "   5xx " + str(counts["5"])
				+ "   Down " + str(counts["down"])
			)
			text = prefix + "   " + detail
		else:
			text = prefix
		self.query_one("#stats", Static).update(text)

	def _set_bucket(self, bucket: str) -> None:
		self.bucket = bucket
		for name in ("all", "2", "3", "4", "5", "down"):
			button = self.query_one("#f-" + name, Button)
			button.variant = "primary" if name == bucket else "default"
		self._rebuild_table()

	def _rebuild_table(self) -> None:
		table = self.query_one("#table", DataTable)
		table.clear()
		for result in self.results:
			if self._visible(result):
				table.add_row(
					status_text(result),
					result.host,
					result.ip or "-",
					cloudflare_text(result),
				)
