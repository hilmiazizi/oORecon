"""Reverse IP phase (A/AAAA from the DNS phase)."""

from textual.widgets import DataTable, Static

from models import ReverseIpHit
from tools.reverseip import ReverseIpError, reverse_ip_lookup


class ReversePhase:
	async def _run_reverse_ip(self, domain: str) -> None:
		if not self.is_running:
			return
		table = self.query_one("#table-reverse", DataTable)
		table.clear()
		self._reverse_hits.clear()
		self._rev_status = "reverse…"
		self._refresh_status()
		self.query_one("#stats-reverse", Static).update("Reverse IP for " + domain + "…")

		await self._dns_done.wait()
		ips = [ip for ip in self._dns_ips if ip]
		if not ips:
			self._rev_status = "reverse 0"
			self._refresh_status()
			self.query_one("#stats-reverse", Static).update("No A/AAAA for " + domain)
			self._log("reverse skipped · no A/AAAA", "yellow")
			return

		self._log("reverse IP · " + str(len(ips)) + " · " + ", ".join(ips[:6]))

		def on_progress(text: str) -> None:
			if not self.is_running:
				return
			self._rev_status = "reverse " + str(len(self._reverse_hits))
			self._refresh_status()
			self.query_one("#stats-reverse", Static).update(text)
			self._log_throttled("reverse · " + text)

		def on_hit(hit: ReverseIpHit) -> None:
			if not self.is_running:
				return
			self._reverse_hits.append(hit)
			table.add_row(hit.ip, hit.host)
			self._log_throttled("reverse · " + hit.ip + " · " + hit.host)

		try:
			hits = await reverse_ip_lookup(
				ips,
				on_progress=on_progress,
				on_hit=on_hit,
			)
		except asyncio.CancelledError:
			self._rev_status = "reverse cancelled"
			self._refresh_status()
			self._log("reverse cancelled", "yellow")
			raise
		except ReverseIpError as exc:
			self._rev_status = "reverse failed"
			self._refresh_status()
			self.query_one("#stats-reverse", Static).update(str(exc))
			self._log("reverse failed: " + str(exc), "bold red")
			self.notify(str(exc), severity="error", timeout=8)
			return

		if self.is_running:
			self._rev_status = "reverse " + str(len(hits))
			self._refresh_status()
			self.query_one("#stats-reverse", Static).update(
				str(len(hits)) + " hosts · " + str(len(ips)) + " IP · enter to open"
			)
			self._log(
				"reverse done · " + str(len(hits)) + " hosts · " + str(len(ips)) + " IP",
				"cyan",
			)
