from __future__ import annotations

import asyncio
import gzip
import re
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

from models import SitemapHit
from utils import call_maybe, cffi_get, http_base

HEADERS = {
	"User-Agent": "Mozilla/5.0 (compatible; oORecon/1.0)",
	"Accept": "*/*",
}

OnProgress = Callable[[str], Awaitable[None] | None]
OnItem = Callable[[object], Awaitable[None] | None]

DEFAULT_CONCURRENCY = 15

WORDLIST_PATH = Path(__file__).resolve().parent / "wordlists" / "sitemap.txt"

# Used when the wordlist file is missing.
FALLBACK_PATHS = (
	"sitemap.xml",
	"sitemap_index.xml",
	"sitemap-index.xml",
)


def load_sitemap_wordlist(path: Path | None = None) -> tuple[str, ...]:
	"""One sitemap path per line. Comments and blanks are skipped."""
	target = path or WORDLIST_PATH
	if not target.is_file():
		return FALLBACK_PATHS
	paths: list[str] = []
	seen: set[str] = set()
	for line in target.read_text(encoding="utf-8", errors="replace").splitlines():
		item = line.strip().lstrip("/")
		if not item or item.startswith("#") or item in seen:
			continue
		seen.add(item)
		paths.append(item)
	return tuple(paths) if paths else FALLBACK_PATHS


def _is_xml_sitemap(url: str) -> bool:
	"""Only .xml / .xml.gz sitemap endpoints — never page URLs."""
	path = urlparse(url).path.lower().rstrip("/")
	return path.endswith(".xml") or path.endswith(".xml.gz")


def _parse_locs(xml_text: str) -> list[str]:
	try:
		root = ElementTree.fromstring(xml_text)
	except ElementTree.ParseError:
		return re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml_text, flags=re.I)
	tag = root.tag
	ns = ""
	if tag.startswith("{"):
		ns = tag.split("}")[0] + "}"
	urls = []
	for loc in root.iter(ns + "loc"):
		if loc.text:
			urls.append(loc.text.strip())
	return urls


def _get_sync(url: str, timeout: float = 25.0) -> tuple[int | None, str]:
	"""Blocking GET — runs in a worker thread."""
	try:
		response = cffi_get(url, headers=HEADERS, timeout=timeout)
		body = response.content or b""
		text = response.text or ""
		if isinstance(text, bytes):
			text = text.decode("utf-8", errors="replace")
		if url.lower().split("?", 1)[0].endswith(".gz") or body.startswith(b"\x1f\x8b"):
			try:
				text = gzip.decompress(body).decode("utf-8", errors="replace")
			except Exception:
				pass
		return response.status_code, text
	except Exception:
		return None, ""


async def find_sitemaps(
	host: str,
	*,
	wordlist: Path | None = None,
	on_progress: OnProgress | None = None,
	on_hit: OnItem | None = None,
) -> list[SitemapHit]:
	"""Recursively discover sitemap URLs.

	Seeds come from robots.txt and the sitemap wordlist. Nested <loc> entries
	that point at another sitemap are followed. Page URLs inside a urlset are ignored.
	"""
	base = http_base(host)
	hits: list[SitemapHit] = []
	seen: set[str] = set()
	emitted: set[str] = set()
	loop = asyncio.get_running_loop()
	workers = DEFAULT_CONCURRENCY

	with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sitemap") as pool:
		async def fetch(url: str, timeout: float = 25.0) -> tuple[int | None, str]:
			return await loop.run_in_executor(pool, _get_sync, url, timeout)

		seeds: list[str] = []
		await call_maybe(on_progress, "robots.txt")
		status, body = await fetch(base + "/robots.txt")
		if status == 200 and body:
			hit = SitemapHit("robots", base + "/robots.txt", "200")
			hits.append(hit)
			await call_maybe(on_hit, hit)
			for line in body.splitlines():
				if line.lower().startswith("sitemap:"):
					seeds.append(line.split(":", 1)[1].strip())
		else:
			await call_maybe(on_progress, "robots.txt missing")

		paths = load_sitemap_wordlist(wordlist)
		await call_maybe(on_progress, "wordlist · " + str(len(paths)) + " paths")
		for path in paths:
			seeds.append(urljoin(base + "/", path))

		queue: list[str] = []
		for url in seeds:
			if url and url not in seen:
				seen.add(url)
				queue.append(url)

		lock = asyncio.Lock()
		sem = asyncio.Semaphore(workers)

		async def emit(url: str, detail: str) -> None:
			hit = SitemapHit("sitemap", url, detail)
			async with lock:
				if url in emitted:
					return
				emitted.add(url)
				hits.append(hit)
			await call_maybe(on_hit, hit)

		async def visit(url: str) -> list[str]:
			await call_maybe(on_progress, "checking " + url)
			async with sem:
				status, body = await fetch(url)
			if status != 200 or not body:
				return []
			await emit(url, "200")

			nested: list[str] = []
			for loc in _parse_locs(body):
				if not _is_xml_sitemap(loc):
					continue
				async with lock:
					if loc in seen:
						continue
					seen.add(loc)
				nested.append(loc)
			return nested

		while queue:
			batch = queue
			queue = []
			for nested in await asyncio.gather(*(visit(url) for url in batch)):
				queue.extend(nested)

	return hits
