from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Iterable

import aiohttp

from models import ReverseIpHit
from utils import call_maybe, is_ip

HEADERS = {
	"Accept": "*/*",
	"Accept-Language": "en-US,en;q=0.9",
	"User-Agent": (
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
		"AppleWebKit/537.36 (KHTML, like Gecko) "
		"Chrome/122.0.0.0 Safari/537.36"
	),
	"Cache-Control": "no-cache",
	"Pragma": "no-cache",
}

API_URL = "https://bgp.he.net/certs/api/ip-search"
# Soft cap so shared anycast IPs (1.1.1.1 etc.) don't run forever.
MAX_PAGES_PER_IP = 25

OnProgress = Callable[[str], Awaitable[None] | None]
OnItem = Callable[[ReverseIpHit], Awaitable[None] | None]


class ReverseIpError(Exception):
	pass


async def _fetch_page(
	session: aiohttp.ClientSession,
	ip: str,
	page: str | None = None,
) -> dict:
	params: dict[str, str] = {"ip": ip}
	if page is not None:
		# Pass the token verbatim — float/int round-trips corrupt large page IDs.
		params["page"] = page
	headers = dict(HEADERS)
	headers["Referer"] = "https://bgp.he.net/ip/" + ip
	try:
		async with session.get(
			API_URL,
			params=params,
			headers=headers,
			timeout=aiohttp.ClientTimeout(total=45),
		) as response:
			text = await response.text()
			if response.status != 200:
				raise ReverseIpError(
					"bgp.he.net HTTP " + str(response.status) + " for " + ip
				)
			try:
				# Keep large integers as strings so next_page stays exact.
				data = json.loads(text, parse_int=str, parse_float=str)
			except json.JSONDecodeError as exc:
				raise ReverseIpError("bgp.he.net bad JSON for " + ip) from exc
			if str(data.get("success", "true")).lower() in {"false", "0"}:
				raise ReverseIpError("bgp.he.net rejected " + ip)
			return data
	except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError) as exc:
		raise ReverseIpError("bgp.he.net unreachable for " + ip) from exc


async def reverse_ip_lookup(
	ips: Iterable[str],
	*,
	on_progress: OnProgress | None = None,
	on_hit: OnItem | None = None,
	max_pages: int = MAX_PAGES_PER_IP,
) -> list[ReverseIpHit]:
	"""Reverse IP → hostnames via Hurricane Electric certificate search API."""
	unique = []
	seen_ip: set[str] = set()
	for ip in ips:
		ip = (ip or "").strip()
		if not ip or not is_ip(ip) or ip in seen_ip:
			continue
		seen_ip.add(ip)
		unique.append(ip)

	hits: list[ReverseIpHit] = []
	seen_host: set[str] = set()
	if not unique:
		await call_maybe(on_progress, "no A/AAAA addresses")
		return hits

	timeout = aiohttp.ClientTimeout(total=45)
	async with aiohttp.ClientSession(headers=HEADERS, timeout=timeout, trust_env=True) as session:
		for index, ip in enumerate(unique, 1):
			await call_maybe(
				on_progress,
				"ip " + str(index) + "/" + str(len(unique)) + " · " + ip,
			)
			page_token: str | None = None
			pages = 0
			ip_new = 0
			while pages < max_pages:
				data = await _fetch_page(session, ip, page_token)
				pages += 1
				before = len(hits)
				for entry in data.get("entries") or []:
					entry_ip = str(entry.get("ip") or ip)
					for host in entry.get("hostnames") or []:
						host = str(host).strip().lower().rstrip(".")
						if not host or host in seen_host:
							continue
						seen_host.add(host)
						hit = ReverseIpHit(entry_ip, host)
						hits.append(hit)
						await call_maybe(on_hit, hit)
				added = len(hits) - before
				ip_new += added
				await call_maybe(
					on_progress,
					"ip "
					+ ip
					+ " · page "
					+ str(pages)
					+ " · +"
					+ str(added)
					+ " new · "
					+ str(len(hits))
					+ " total",
				)
				# Same page / empty page — stop (CF shared IPs often repeat).
				if added == 0:
					break
				has_more = data.get("has_more")
				if str(has_more).lower() in {"false", "0", "none", ""}:
					break
				next_page = data.get("next_page")
				if next_page is None or str(next_page) == str(page_token or ""):
					break
				page_token = str(next_page)
			await call_maybe(
				on_progress,
				"ip " + ip + " · +" + str(ip_new) + " new · " + str(len(hits)) + " total",
			)

	await call_maybe(on_progress, "done · " + str(len(hits)) + " hosts")
	return hits
