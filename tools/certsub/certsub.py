import asyncio
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor

import aiohttp

from models import HostResult
from utils import call_maybe, normalize_domain, probe_https

HEADERS = {
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Accept": "text/plain,*/*;q=0.8",
}

OnHosts = Callable[[list[str]], Awaitable[None] | None]
OnCheck = Callable[[str], Awaitable[None] | None]
OnResult = Callable[["HostResult", int, int], Awaitable[None] | None]

DEFAULT_CONCURRENCY = 50
DEFAULT_TIMEOUT = 2.0


class CertSubError(Exception):
	pass


def _extract(body: str, domain: str) -> list[str]:
	storage = set()
	suffix = "." + domain
	for line in body.replace("\r", "\n").split("\n"):
		host = line.strip().lower().rstrip(".")
		if not host or "*" in host or "@" in host or " " in host:
			continue
		if host.startswith("www."):
			host = host[4:]
		if host == domain or host.endswith(suffix):
			storage.add(host)
	# Always include the looked-up apex, even when CT has only subdomains.
	storage.add(domain)
	hosts = sorted(storage)
	# Keep apex first in the subdomain table.
	return [domain] + [host for host in hosts if host != domain]


async def _fetch_names(session: aiohttp.ClientSession, domain: str) -> str:
	params = {"apex": domain}
	message = "Can't Get Records!"
	for attempt in range(5):
		try:
			async with session.get(
				"https://crt.name/v1/search",
				params=params,
				timeout=aiohttp.ClientTimeout(total=90),
			) as response:
				if response.status == 200:
					return await response.text()
				if response.status in (429, 502, 503, 504):
					message = "Can't Access crt.name, try again or change your IP"
				else:
					message = "Can't Get Records!"
		except (aiohttp.ClientError, TimeoutError):
			message = "Can't Access crt.name, try again or change your IP"
		await asyncio.sleep(2 + attempt * 2)
	raise CertSubError(message)


def _check_sync(host: str, timeout: float) -> tuple[str | None, bool, str | None]:
	"""Blocking HTTPS probe — safe to run in a worker thread.

	Returns (status, cloudflare, primary_ip).
	"""
	status, ip, cloudflare = probe_https(host, timeout)
	return status, cloudflare, ip


async def certsub(
	domain: str,
	*,
	concurrency: int = DEFAULT_CONCURRENCY,
	timeout: float = DEFAULT_TIMEOUT,
	on_hosts: OnHosts | None = None,
	on_check: OnCheck | None = None,
	on_result: OnResult | None = None,
) -> list[HostResult]:
	"""Fetch certificate names for domain and check each host over HTTPS.

	Certificate names come from crt.name (aiohttp). Host checks use curl_cffi
	sync Session in a thread pool (Chrome TLS impersonation) so blocking DNS
	cannot freeze the asyncio/TUI loop.
	"""
	domain = normalize_domain(domain)
	if not domain:
		raise CertSubError("invalid domain")
	if concurrency < 1:
		concurrency = 1

	connector = aiohttp.TCPConnector(
		limit=32,
		ttl_dns_cache=300,
		enable_cleanup_closed=True,
	)
	async with aiohttp.ClientSession(headers=HEADERS, connector=connector, trust_env=True) as http:
		body = await _fetch_names(http, domain)
	# Large CT dumps can stall the event loop if parsed inline.
	hosts = await asyncio.to_thread(_extract, body, domain)
	await call_maybe(on_hosts, hosts)

	total = len(hosts)
	if total == 0:
		return []

	workers = min(concurrency, total)
	queue: asyncio.Queue[str | None] = asyncio.Queue()
	for host in hosts:
		queue.put_nowait(host)
	for _ in range(workers):
		queue.put_nowait(None)

	results: list[HostResult] = []
	done = 0
	lock = asyncio.Lock()
	loop = asyncio.get_running_loop()

	with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="certsub") as pool:
		async def worker() -> None:
			nonlocal done
			while True:
				host = await queue.get()
				if host is None:
					return
				await call_maybe(on_check, host)
				status, cloudflare, ip = await loop.run_in_executor(
					pool,
					_check_sync,
					host,
					timeout,
				)
				result = HostResult(host, status, ip, cloudflare)
				async with lock:
					results.append(result)
					done += 1
					current = done
				await call_maybe(on_result, result, current, total)
				await asyncio.sleep(0)

		await asyncio.gather(*(worker() for _ in range(workers)))

	return sorted(results, key=lambda item: item.host)
