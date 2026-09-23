"""DNS lookup phase for the main recon app."""

import asyncio

from textual.widgets import Static

from models import DnsInfo
from tools.dnsinfo import DnsError, lookup
from ui.format import dns_board


class DnsPhase:
	async def _run_dns(self, domain: str) -> None:
		if not self.is_running:
			return
		self._dns_status = "dns…"
		self._refresh_status()
		self.query_one("#dns-stats", Static).update("Fetching DNS for " + domain)
		self.query_one("#dns-view", Static).update("")
		self._log("resolving DNS for " + domain + "...")
		try:
			info = await lookup(domain)
		except asyncio.CancelledError:
			self._dns_status = "dns cancelled"
			self._refresh_status()
			self._log("dns cancelled", "yellow")
			self._dns_done.set()
			raise
		except DnsError as exc:
			if self.is_running:
				self._dns_status = "dns failed"
				self._refresh_status()
				self.query_one("#dns-stats", Static).update(str(exc))
				self.query_one("#dns-view", Static).update("")
				self._log("dns failed: " + str(exc), "bold red")
				self.notify(str(exc), severity="error", timeout=8)
			self._dns_done.set()
			return
		if self.is_running:
			self._show_dns(info)
		self._dns_done.set()

	def _show_dns(self, info: DnsInfo) -> None:
		self.query_one("#dns-view", Static).update(dns_board(info))
		# Reverse IP uses only this domain's A / AAAA records.
		self._dns_ips = list(info.ips)
		if info.exposes_ip:
			summary = info.domain + "   " + str(len(info.ips)) + " IP addresses"
			self._dns_status = str(len(info.ips)) + " ip"
			self._log(
				"dns ok · " + str(len(info.ips)) + " IP · " + ", ".join(info.ips[:4]),
				"cyan",
			)
		elif info.sections:
			summary = info.domain + "   no IP addresses"
			self._dns_status = "dns ok"
			self._log("dns ok · " + str(len(info.sections)) + " sections", "cyan")
		else:
			summary = info.domain + "   no DNS records"
			self._dns_status = "dns empty"
			self._log("dns empty", "yellow")
		self.query_one("#dns-stats", Static).update(summary)
		self._refresh_status()
