"""Shared helpers for oORecon tools and UI."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Mapping
from urllib.parse import urlparse

# Browser TLS fingerprint for requests to discovered targets (not third-party APIs).
CFFI_IMPERSONATE = "chrome"


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


def cffi_get(
	url: str,
	*,
	headers: Mapping[str, str] | None = None,
	timeout: float = 10.0,
	allow_redirects: bool = True,
	max_redirects: int = 5,
):
	"""One-shot curl_cffi GET. Nothing is reused."""
	from curl_cffi.requests import get

	return get(
		url,
		impersonate=CFFI_IMPERSONATE,
		headers=dict(headers) if headers else None,
		timeout=timeout,
		allow_redirects=allow_redirects,
		max_redirects=max_redirects,
	)


def probe_https(host: str, timeout: float = 2.0) -> tuple[str | None, str | None, bool]:
	"""One-shot HTTPS GET for status, connected IP, and Cloudflare."""
	try:
		response = cffi_get("https://" + host, timeout=timeout)
		status = str(response.status_code)
		ip = (getattr(response, "primary_ip", None) or "").strip() or None
		return status, ip, is_cloudflare(response.headers)
	except Exception as exc:
		name = type(exc).__name__.lower()
		if "timeout" in name or "timed out" in str(exc).lower():
			return None, None, False
		return None, None, False


async def call_maybe(callback, *args) -> None:
	"""Invoke an optional sync/async callback."""
	if callback is None:
		return
	result = callback(*args)
	if asyncio.iscoroutine(result):
		await result
