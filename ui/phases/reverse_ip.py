"""Reverse IP phase (A/AAAA from the DNS phase)."""

import asyncio
from concurrent.futures import ThreadPoolExecutor

from rich.text import Text
from textual.widgets import DataTable, Static

from models import ReverseIpHit
from tools.reverseip import ReverseIpError, reverse_ip_lookup
from ui.format import cloudflare_text, status_text
from utils import probe_https

# Same cap as subdomain checks — curl DNS must stay off the UI thread.
CHECK_CONCURRENCY = 50
CHECK_TIMEOUT = 2.0


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
			table.add_row(
				Text("…", style="dim"),
				hit.host,
				hit.ip,
				Text("…", style="dim"),
				key=hit.host,
			)
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

		if not self.is_running:
			return
		if not hits:
			self._rev_status = "reverse 0"
			self._refresh_status()
			self.query_one("#stats-reverse", Static).update(
				"0 hosts · " + str(len(ips)) + " IP"
			)
			self._log("reverse done · 0 hosts · " + str(len(ips)) + " IP", "cyan")
			return

		try:
			checked = await self._check_reverse_hits(hits)
		except asyncio.CancelledError:
			self._rev_status = "reverse cancelled"
			self._refresh_status()
			self._log("reverse cancelled", "yellow")
			raise

		if self.is_running:
			self._reverse_hits[:] = checked
			self._rev_status = "reverse " + str(len(checked))
			self._refresh_status()
			self.query_one("#stats-reverse", Static).update(
				str(len(checked)) + " hosts · " + str(len(ips)) + " IP · enter to open"
			)
			self._log(
				"reverse done · " + str(len(checked)) + " hosts · " + str(len(ips)) + " IP",
				"cyan",
			)

	async def _check_reverse_hits(self, hits: list[ReverseIpHit]) -> list[ReverseIpHit]:
		"""HTTPS status + Cloudflare for each reverse-IP hostname."""
		total = len(hits)
		workers = min(CHECK_CONCURRENCY, total)
		queue: asyncio.Queue[ReverseIpHit | None] = asyncio.Queue()
		for hit in hits:
			queue.put_nowait(hit)
		for _ in range(workers):
			queue.put_nowait(None)

		checked: list[ReverseIpHit] = []
		done = 0
		lock = asyncio.Lock()
		loop = asyncio.get_running_loop()
		table = self.query_one("#table-reverse", DataTable)
		self._log("reverse · checking " + str(total) + " hosts...")

		with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="reverse") as pool:
			async def worker() -> None:
				nonlocal done
				while True:
					hit = await queue.get()
					if hit is None:
						return
					status, _ip, cloudflare = await loop.run_in_executor(
						pool,
						probe_https,
						hit.host,
						CHECK_TIMEOUT,
					)
					updated = ReverseIpHit(hit.ip, hit.host, status, cloudflare)
					async with lock:
						checked.append(updated)
						done += 1
						current = done
					if self.is_running:
						table.update_cell(hit.host, "status", status_text(updated))
						table.update_cell(hit.host, "cf", cloudflare_text(updated))
						self._rev_status = "reverse " + str(current) + "/" + str(total)
						if current == total or current % 10 == 0:
							self._refresh_status()
							self.query_one("#stats-reverse", Static).update(
								"checking " + str(current) + "/" + str(total)
							)
						label = status or "down"
						cf = "cf:yes" if cloudflare else "cf:no"
						if status and status.startswith("2"):
							self._log(hit.host + " · " + label + " · " + hit.ip + " · " + cf)
						else:
							self._log_throttled(
								hit.host + " · " + label + " · " + hit.ip + " · " + cf
							)
					await asyncio.sleep(0)

			await asyncio.gather(*(worker() for _ in range(workers)))

		order = {hit.host: index for index, hit in enumerate(hits)}
		checked.sort(key=lambda item: order.get(item.host, 0))
		return checked
