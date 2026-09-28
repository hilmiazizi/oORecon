from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from models import DirHit
from utils import call_maybe, cffi_get, http_base

HEADERS = {
	"User-Agent": "Mozilla/5.0 (compatible; oORecon/1.0)",
	"Accept": "*/*",
}

# SecLists Discovery/Web-Content/common.txt — the usual ffuf starter wordlist.
WORDLIST_PATH = Path(__file__).resolve().parent / "wordlists" / "common.txt"

FALLBACK_PATHS = (
	"admin", "administrator", "api", "backup", "bin", "config", "console",
	"dashboard", "debug", "dev", "docs", "env", ".env", "graphql", "internal",
	"login", "manage", "management", "metrics", "phpinfo.php", "private",
	"robots.txt", "server-status", "sitemap.xml", "staging", "status",
	"swagger", "test", "upload", "uploads", "wp-admin", "wp-login.php",
	".git/HEAD", ".svn/entries", "actuator", "actuator/health", "health",
	"healthz", "ready", "version", "v1", "v2", "assets", "static", "js",
)

OnProgress = Callable[[str], Awaitable[None] | None]
OnItem = Callable[[object], Awaitable[None] | None]

DEFAULT_CONCURRENCY = 50
# Soft-404s (Instagram's HTML shell) share this prefix; nonces and the path come later.
_WILDCARD_BYTES = 256


def load_wordlist(path: Path | None = None) -> tuple[str, ...]:
	"""Load ffuf-style SecLists common.txt (one path per line)."""
	target = path or WORDLIST_PATH
	if not target.is_file():
		return FALLBACK_PATHS
	paths: list[str] = []
	seen: set[str] = set()
	for line in target.read_text(encoding="utf-8", errors="replace").splitlines():
		item = line.strip()
		if not item or item.startswith("#"):
			continue
		if item in seen:
			continue
		seen.add(item)
		paths.append(item)
	return tuple(paths) if paths else FALLBACK_PATHS


DEFAULT_PATHS = load_wordlist()


def _probe_sync(url: str, timeout: float) -> tuple[int | None, int, bytes]:
	"""Blocking GET — runs in a worker thread (no AsyncSession on the UI loop)."""
	try:
		response = cffi_get(url, headers=HEADERS, allow_redirects=False, timeout=timeout)
		body = response.content or b""
		cl = response.headers.get("Content-Length") or response.headers.get("content-length")
		if cl is not None and str(cl).isdigit():
			length = int(cl)
		else:
			length = len(body)
		return response.status_code, length, body[:_WILDCARD_BYTES]
	except Exception:
		return None, 0, b""


async def brute_dirs(
	host: str,
	*,
	paths: tuple[str, ...] | None = None,
	wordlist: Path | None = None,
	concurrency: int = DEFAULT_CONCURRENCY,
	timeout: float = 8.0,
	on_progress: OnProgress | None = None,
	on_hit: OnItem | None = None,
) -> list[DirHit]:
	base = http_base(host)
	word_paths = paths if paths is not None else load_wordlist(wordlist)
	total = len(word_paths)
	if concurrency < 1:
		concurrency = 1
	workers = min(concurrency, max(total, 1))
	hits: list[DirHit] = []
	done = 0
	lock = asyncio.Lock()
	loop = asyncio.get_running_loop()

	await call_maybe(on_progress, "0/" + str(total) + " · " + str(total) + " paths")

	# One missing path. Anything that comes back identical is the site-wide soft 404.
	wildcard: tuple[int, bytes] | None = None

	queue: asyncio.Queue[str | None] = asyncio.Queue()
	for path in word_paths:
		queue.put_nowait(path)
	for _ in range(workers):
		queue.put_nowait(None)

	with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dirbrute") as pool:
		baseline = base + "/oorecon-" + uuid.uuid4().hex
		base_status, _, base_prefix = await loop.run_in_executor(
			pool, _probe_sync, baseline, timeout
		)
		if base_status is not None and base_prefix:
			wildcard = (base_status, base_prefix)
			await call_maybe(on_progress, "wildcard · HTTP " + str(base_status))

		async def worker() -> None:
			nonlocal done
			while True:
				path = await queue.get()
				if path is None:
					return
				url = base + "/" + path.lstrip("/")
				status, length, prefix = await loop.run_in_executor(pool, _probe_sync, url, timeout)
				same_shell = (
					wildcard is not None
					and status == wildcard[0]
					and prefix == wildcard[1]
				)
				if (
					status is not None
					and (status < 400 or status in (401, 403))
					and length > 0
					and not same_shell
				):
					hit = DirHit(path, status, length, url)
					async with lock:
						hits.append(hit)
					await call_maybe(on_hit, hit)
				async with lock:
					done += 1
					current = done
				await call_maybe(on_progress, str(current) + "/" + str(total))
				await asyncio.sleep(0)

		await asyncio.gather(*(worker() for _ in range(workers)))

	return sorted(hits, key=lambda item: (item.status, item.path))
