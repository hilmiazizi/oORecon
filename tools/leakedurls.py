"""Hudson Rock leaked login URL lookup (third-party API → aiohttp)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from urllib.parse import quote

import aiohttp

from models import LeakedUrlHit
from utils import call_maybe, normalize_domain

API_URL = "https://www.hudsonrock.com/api/json/v2/stats/website-results/urls/{domain}"

HEADERS = {
	"Accept": "*/*",
	"Accept-Language": "en-US,en;q=0.9",
	"Content-Type": "application/json",
	"User-Agent": (
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
		"AppleWebKit/537.36 (KHTML, like Gecko) "
		"Chrome/122.0.0.0 Safari/537.36"
	),
}

OnProgress = Callable[[str], Awaitable[None] | None]
OnItem = Callable[[LeakedUrlHit], Awaitable[None] | None]


class LeakedUrlError(Exception):
	pass


async def leaked_login_urls(
	domain: str,
	*,
	on_progress: OnProgress | None = None,
	on_hit: OnItem | None = None,
) -> list[LeakedUrlHit]:
	"""Fetch leaked login / credential URLs for a domain from Hudson Rock."""
	domain = normalize_domain(domain)
	if not domain:
		raise LeakedUrlError("invalid domain")

	await call_maybe(on_progress, "fetching " + domain)
	url = API_URL.format(domain=quote(domain, safe="."))
	headers = dict(HEADERS)
	headers["Referer"] = "https://www.hudsonrock.com/search/domain/" + domain

	timeout = aiohttp.ClientTimeout(total=60)
	try:
		async with aiohttp.ClientSession(headers=HEADERS, timeout=timeout, trust_env=True) as session:
			async with session.get(url, headers=headers) as response:
				text = await response.text()
				if response.status != 200:
					raise LeakedUrlError(
						"hudsonrock HTTP " + str(response.status) + " for " + domain
					)
	except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError) as exc:
		raise LeakedUrlError("hudsonrock unreachable for " + domain) from exc

	try:
		payload = json.loads(text)
	except json.JSONDecodeError as exc:
		raise LeakedUrlError("hudsonrock bad JSON for " + domain) from exc

	data = payload.get("data") if isinstance(payload, dict) else None
	if not isinstance(data, dict):
		raise LeakedUrlError("hudsonrock unexpected response for " + domain)

	# Prefer all_urls; fall back to employees + clients.
	raw_entries = data.get("all_urls")
	if not isinstance(raw_entries, list) or not raw_entries:
		raw_entries = []
		for key in ("employees_urls", "clients_urls"):
			chunk = data.get(key)
			if isinstance(chunk, list):
				raw_entries.extend(chunk)

	hits: list[LeakedUrlHit] = []
	seen: set[str] = set()
	for entry in raw_entries:
		if not isinstance(entry, dict):
			continue
		item_url = str(entry.get("url") or "").strip()
		if not item_url or item_url in seen:
			continue
		seen.add(item_url)
		kind = str(entry.get("type") or "Unknown").strip() or "Unknown"
		try:
			occurrence = int(entry.get("occurrence") or 1)
		except (TypeError, ValueError):
			occurrence = 1
		hit = LeakedUrlHit(item_url, kind, max(occurrence, 1))
		hits.append(hit)
		await call_maybe(on_hit, hit)

	hits.sort(key=lambda item: (-item.occurrence, item.url))
	total = payload.get("totalUrls") if isinstance(payload, dict) else len(hits)
	await call_maybe(
		on_progress,
		"done · " + str(len(hits)) + " urls · api total " + str(total),
	)
	return hits
