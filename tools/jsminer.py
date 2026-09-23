from __future__ import annotations

import asyncio
import os
import re
import tempfile
from collections.abc import Awaitable, Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings, get_settings, transient_settings

from models import JsHit
from utils import call_maybe, cffi_close_thread_sessions, cffi_thread_session, http_base

HEADERS = {
	"User-Agent": "Mozilla/5.0 (compatible; oORecon/1.0)",
	"Accept": "*/*",
}

# LinkFinder-style URL extraction used by JSFinder.
_URL_RE = re.compile(
	r"""(?:"|')("""
	r"""((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})"""
	r"""|"""
	r"""((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})"""
	r"""|"""
	r"""([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|/][^"|']{0,}|))"""
	r"""|"""
	r"""([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^"|']{0,}|))"""
	r""")(?:"|')""",
	re.VERBOSE,
)

# Yelp detect-secrets plugins — skip high-entropy scanners (noisy on minified JS/base64).
_DETECT_SKIP_PLUGINS = frozenset(
	{
		"Base64HighEntropyString",
		"HexHighEntropyString",
		"IPPublicDetector",
	}
)
_SECRET_VALUE_MAX = 240
_SECRET_CONTEXT_RADIUS = 120
DEFAULT_CONCURRENCY = 50

OnProgress = Callable[[str], Awaitable[None] | None]
OnItem = Callable[[object], Awaitable[None] | None]


def _detect_config() -> dict:
	with default_settings():
		names = [name for name in get_settings().plugins if name not in _DETECT_SKIP_PLUGINS]
	return {"plugins_used": [{"name": name} for name in names]}


def _kind_slug(secret_type: str) -> str:
	return re.sub(r"[^a-z0-9]+", "_", (secret_type or "secret").lower()).strip("_") or "secret"


def _clip_secret(value: str) -> str:
	value = value.strip()
	if len(value) > _SECRET_VALUE_MAX:
		return value[:_SECRET_VALUE_MAX] + "…"
	return value


def _context_around(body: str, value: str, line: str) -> str:
	"""Neighbors around the secret in its source line / body."""
	haystack = line if value and value in line else body
	idx = haystack.find(value) if value else -1
	if idx < 0:
		snippet = haystack[: _SECRET_CONTEXT_RADIUS * 2]
		return snippet + ("…" if len(haystack) > len(snippet) else "")
	lo = max(0, idx - _SECRET_CONTEXT_RADIUS)
	hi = min(len(haystack), idx + len(value) + _SECRET_CONTEXT_RADIUS)
	snippet = haystack[lo:hi].replace("\r\n", "\n").replace("\r", "\n")
	prefix = "…" if lo > 0 else ""
	suffix = "…" if hi < len(haystack) else ""
	return prefix + snippet + suffix


def _extract_secrets(text: str) -> list[tuple[str, str, str]]:
	"""Scan JS with detect-secrets → (kind, value, context)."""
	body = text or ""
	if not body.strip():
		return []

	fd, path = tempfile.mkstemp(suffix=".js")
	try:
		os.write(fd, body.encode("utf-8", errors="replace"))
		os.close(fd)
		fd = -1
		collection = SecretsCollection()
		with transient_settings(_detect_config()):
			collection.scan_file(path)
	finally:
		if fd >= 0:
			os.close(fd)
		try:
			os.unlink(path)
		except OSError:
			pass

	lines = body.splitlines() or [body]
	found: list[tuple[str, str, str]] = []
	seen: set[str] = set()
	for _filename, items in collection.data.items():
		for secret in items:
			value = _clip_secret(getattr(secret, "secret_value", None) or "")
			if not value:
				continue
			kind = _kind_slug(secret.type)
			key = kind + "|" + value
			if key in seen:
				continue
			seen.add(key)
			line_no = int(getattr(secret, "line_number", 0) or 0)
			line = lines[line_no - 1] if 0 < line_no <= len(lines) else body
			found.append((kind, value, _context_around(body, value, line)))
	return found


class _ScriptParser(HTMLParser):
	def __init__(self) -> None:
		super().__init__(convert_charrefs=True)
		self.scripts: list[str] = []
		self.inline: list[str] = []
		self._in_script = False
		self._buf: list[str] = []

	def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
		if tag != "script":
			return
		src = dict(attrs).get("src")
		if src:
			self.scripts.append(src)
		else:
			self._in_script = True
			self._buf = []

	def handle_endtag(self, tag: str) -> None:
		if tag == "script" and self._in_script:
			self.inline.append("".join(self._buf))
			self._in_script = False
			self._buf = []

	def handle_data(self, data: str) -> None:
		if self._in_script:
			self._buf.append(data)


def _resolve(base: str, value: str) -> str:
	value = value.strip()
	if not value or value.startswith("javascript:"):
		return ""
	if value.startswith("//"):
		scheme = urlparse(base).scheme or "https"
		return scheme + ":" + value
	return urljoin(base if base.endswith("/") else base + "/", value)


def _extract_urls(text: str) -> list[str]:
	found = []
	for match in _URL_RE.finditer(text or ""):
		item = match.group().strip("\"'")
		if item and item not in found:
			found.append(item)
	return found


def _get_sync(url: str, timeout: float = 25.0) -> str:
	"""Blocking GET — runs in a worker thread."""
	try:
		response = cffi_thread_session(HEADERS).get(
			url,
			allow_redirects=True,
			timeout=timeout,
		)
		if response.status_code >= 400:
			return ""
		text = response.text or ""
		if isinstance(text, bytes):
			return text.decode("utf-8", errors="replace")
		return text
	except Exception:
		return ""


async def mine_js(
	host: str,
	*,
	targets: Sequence[str] | None = None,
	concurrency: int = DEFAULT_CONCURRENCY,
	on_progress: OnProgress | None = None,
	on_hit: OnItem | None = None,
) -> list[JsHit]:
	"""JSFinder-style URL mining plus Yelp detect-secrets for keys/tokens.

	If targets is set (e.g. main page + directory 200 URLs), each page is mined.
	Otherwise mines the host apex.
	"""
	if targets:
		pages = [http_base(item) for item in targets]
	else:
		pages = [http_base(host)]
	ordered: list[str] = []
	seen_pages: set[str] = set()
	for page in pages:
		if page not in seen_pages:
			seen_pages.add(page)
			ordered.append(page)

	hits: list[JsHit] = []
	seen: set[str] = set()
	root = urlparse(http_base(host)).hostname or host
	if concurrency < 1:
		concurrency = 1
	workers = min(concurrency, 50)
	loop = asyncio.get_running_loop()

	async def emit(kind: str, value: str, source: str = "", context: str = "") -> None:
		key = kind + "|" + value + "|" + context[:40]
		if not value or key in seen:
			return
		seen.add(key)
		hit = JsHit(kind, value, source, context)
		hits.append(hit)
		await call_maybe(on_hit, hit)

	with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="jsminer") as pool:
		async def fetch(url: str) -> str:
			return await loop.run_in_executor(pool, _get_sync, url)

		try:
			for index, base in enumerate(ordered, 1):
				await call_maybe(
					on_progress,
					"page " + str(index) + "/" + str(len(ordered)) + " · " + base,
				)
				html = await fetch(base)
				if not html:
					continue

				parser = _ScriptParser()
				try:
					parser.feed(html)
				except Exception:
					continue

				script_urls = []
				for src in parser.scripts:
					resolved = _resolve(base, src)
					if resolved:
						script_urls.append(resolved)
						await emit("script", resolved, base)

				bodies: list[tuple[str, str]] = [("inline", "\n".join(parser.inline))]
				if script_urls:
					await call_maybe(
						on_progress,
						"js 0/" + str(len(script_urls)) + " · " + base,
					)
					fetched = await asyncio.gather(*(fetch(url) for url in script_urls))
					for script_url, body in zip(script_urls, fetched):
						bodies.append((script_url, body))

				for source, body in bodies:
					src_label = source if source != "inline" else base
					for raw in _extract_urls(body):
						resolved = _resolve(source if source.startswith("http") else base, raw)
						if not resolved:
							continue
						host_name = urlparse(resolved).hostname or ""
						if host_name and root not in host_name and not resolved.startswith("/"):
							if not resolved.endswith(".js"):
								continue
						kind = "endpoint" if urlparse(resolved).path else "url"
						if resolved.endswith(".js"):
							kind = "script"
						await emit(kind, resolved, src_label)
					for name, value, context in await asyncio.to_thread(_extract_secrets, body):
						await emit(name, value, src_label, context)
				await asyncio.sleep(0)
		finally:
			closes = [
				loop.run_in_executor(pool, cffi_close_thread_sessions) for _ in range(workers)
			]
			await asyncio.gather(*closes, return_exceptions=True)

	await call_maybe(on_progress, "done · " + str(len(hits)) + " findings")
	return hits
