"""Port scan phase for the looked-up domain."""

import asyncio

from rich.text import Text
from textual.widgets import DataTable, ProgressBar, Static

from models import PortHit
from tools.ports import COMMON_PORTS, scan_ports

PORT_LOG_INTERVAL = 0.08


class PortsPhase:
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
