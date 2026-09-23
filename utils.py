"""Shared helpers for oORecon tools and UI."""

from __future__ import annotations

import asyncio
import ipaddress
import threading
from collections.abc import Mapping
from urllib.parse import urlparse

from curl_cffi.requests import Session

# Browser TLS fingerprint for requests to discovered targets (not third-party APIs).
CFFI_IMPERSONATE = "chrome"

# curl_cffi's bundled libcurl has no AsynchDNS — never use AsyncSession on the
# asyncio/TUI thread. Prefer sync Session via these helpers + ThreadPoolExecutor.
_thread_local = threading.local()


def normalize_domain(raw: str) -> str:
	"""Turn URL or host input into a bare lowercase apex hostname.

	Examples:
	  https://www.crunchbase.com/  → crunchbase.com
	  http://Example.COM:443/path  → example.com
	  example.com.                 → example.com
	"""
	value = (raw or "").strip()
	if not value:
		return ""
	# Bare host/path without scheme — urlparse treats it as path otherwise.
	if "://" not in value:
		value = "http://" + value
	parsed = urlparse(value)
	host = (parsed.hostname or "").lower().rstrip(".")
	if host.startswith("www."):
		host = host[4:]
	return host


def dns_name(value) -> str:
	"""DNS label / name as a plain string without a trailing dot."""
	return str(value).rstrip(".")


def http_base(host: str) -> str:
	"""Absolute http(s) origin for a host or URL (no trailing slash)."""
	if host.startswith("http://") or host.startswith("https://"):
		return host.rstrip("/")
	return "https://" + host.rstrip("/")


def is_ip(value: str) -> bool:
	try:
		ipaddress.ip_address(value)
		return True
	except ValueError:
		return False


def is_cloudflare(headers) -> bool:
	"""Detect Cloudflare from response headers."""
	try:
		items = headers.items()
	except Exception:
		return False
	lower = {str(key).lower(): str(value).lower() for key, value in items}
	if any(
		key in lower
		for key in ("cf-ray", "cf-cache-status", "cf-request-id", "cf-connecting-ip")
	):
		return True
	if "cloudflare" in lower.get("server", ""):
		return True
	if "cloudflare" in lower.get("via", ""):
		return True
	return False


def cffi_thread_session(headers: Mapping[str, str] | None = None) -> Session:
	"""Per-thread curl_cffi Session (safe for blocking DNS/TLS off the UI loop)."""
	bucket = getattr(_thread_local, "cffi_sessions", None)
	if bucket is None:
		bucket = {}
		_thread_local.cffi_sessions = bucket
	key = tuple(sorted((headers or {}).items()))
	session = bucket.get(key)
	if session is None:
		kwargs: dict = {"impersonate": CFFI_IMPERSONATE}
		if headers:
			kwargs["headers"] = dict(headers)
		session = Session(**kwargs)
		bucket[key] = session
	return session


def cffi_close_thread_sessions() -> None:
	"""Close curl sessions bound to the current worker thread."""
	bucket = getattr(_thread_local, "cffi_sessions", None)
	if not bucket:
		return
	for session in bucket.values():
		try:
			session.close()
		except Exception:
			pass
	_thread_local.cffi_sessions = {}


async def call_maybe(callback, *args) -> None:
	"""Invoke an optional sync/async callback."""
	if callback is None:
		return
	result = callback(*args)
	if asyncio.iscoroutine(result):
		await result
