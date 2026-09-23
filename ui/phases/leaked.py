"""Leaked login URL phase."""

from textual.widgets import DataTable, Static

from models import LeakedUrlHit
from tools.leakedurls import LeakedUrlError, leaked_login_urls


class LeakedPhase:
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
