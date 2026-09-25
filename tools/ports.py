from __future__ import annotations

import asyncio
import ssl
from collections.abc import Awaitable, Callable

from models import PortHit
from utils import call_maybe

from .shodan_ports import SHODAN_PORTS

OnProgress = Callable[[int, int], Awaitable[None] | None]
OnProbe = Callable[[int], Awaitable[None] | None]
OnItem = Callable[[PortHit], Awaitable[None] | None]

__all__ = ["COMMON_PORTS", "PortHit", "SHODAN_PORTS", "scan_ports"]

PORT_SERVICES = {
	21: "ftp",
	22: "ssh",
	23: "telnet",
	25: "smtp",
	53: "dns",
	80: "http",
	110: "pop3",
	111: "rpcbind",
	135: "msrpc",
	139: "netbios",
	143: "imap",
	443: "https",
	445: "smb",
	993: "imaps",
	995: "pop3s",
	1433: "mssql",
	1521: "oracle",
	2049: "nfs",
	3306: "mysql",
	3389: "rdp",
	5432: "postgres",
	5900: "vnc",
	6379: "redis",
	8080: "http-proxy",
	8443: "https-alt",
	9200: "elasticsearch",
	27017: "mongodb",
}

# Shodan-style port set (~3800 ports), not a tiny top-N list.
COMMON_PORTS = SHODAN_PORTS


def _http_probe(host: str) -> bytes:
	"""GET so the banner includes a body (Elasticsearch puts its version there)."""
	try:
		host_bytes = host.encode("idna")
	except UnicodeError:
		host_bytes = host.encode("ascii", "ignore")
	return b"GET / HTTP/1.0\r\nHost: " + host_bytes + b"\r\n\r\n"


def _tls_label(writer: asyncio.StreamWriter) -> str:
	obj = writer.get_extra_info("ssl_object")
	if obj is None:
		return ""
	version = obj.version() or "TLS"
	cipher = obj.cipher()
	name = cipher[0] if cipher else ""
	return (version + " " + name).strip()


async def _open(host: str, port: int, timeout: float):
	"""TLS ports handshake first. A failed handshake falls back to plaintext."""
	if port in TLS_PORTS:
		try:
			return await asyncio.wait_for(
				asyncio.open_connection(
					host,
					port,
					ssl=_SSL,
					server_hostname=host,
				),
				timeout=timeout,
			)
		except (ssl.SSLError, asyncio.TimeoutError, OSError, ConnectionError):
			pass
	return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
# Plaintext HTTP. 9200 is Elasticsearch's HTTP API, not a binary port.
HTTP_PROBE_PORTS = {
	80, 81, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8888, 9000, 9080, 9200,
}
TLS_PORTS = {443, 8443, 9443, 10443, 11443, 12443, 60443}
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


async def scan_ports(
	host: str,
	*,
	ports: tuple[int, ...] = COMMON_PORTS,
	timeout: float = 1.5,
	concurrency: int = 400,
	on_progress: OnProgress | None = None,
	on_probe: OnProbe | None = None,
	on_hit: OnItem | None = None,
) -> list[PortHit]:
	sem = asyncio.Semaphore(concurrency)
	hits: list[PortHit] = []
	done = 0
	lock = asyncio.Lock()
	total = len(ports)

	async def one(port: int) -> None:
		nonlocal done
		service = PORT_SERVICES.get(port, "")
		raw = ""
		banner = ""
		try:
			async with sem:
				await call_maybe(on_probe, port)
				reader, writer = await _open(host, port, timeout)
			try:
				if port in TLS_PORTS:
					service = service or "https"
				if port in HTTP_PROBE_PORTS or port in TLS_PORTS:
					writer.write(_http_probe(host))
				else:
					writer.write(b"\r\n")
				await writer.drain()
				try:
					data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
					raw = data.decode("utf-8", "replace")
					banner = " ".join(raw.replace("\r", "\n").split())
				except (asyncio.TimeoutError, ConnectionError, ssl.SSLError):
					raw = ""
					banner = ""
				if not banner and port in TLS_PORTS:
					banner = _tls_label(writer)
					raw = banner
			finally:
				writer.close()
				try:
					await writer.wait_closed()
				except Exception:
					pass
			if not service and banner:
				lower = banner.lower()
				if lower.startswith("http/"):
					service = "http"
				elif "ssh" in lower:
					service = "ssh"
				elif "ftp" in lower:
					service = "ftp"
				elif "smtp" in lower:
					service = "smtp"
			hit = PortHit(host, port, banner, raw, service, "open")
			async with lock:
				hits.append(hit)
				await call_maybe(on_hit, hit)
		except (asyncio.TimeoutError, OSError, ConnectionError):
			pass
		async with lock:
			done += 1
			await call_maybe(on_progress, done, total)

	await call_maybe(on_progress, 0, total)
	await asyncio.gather(*(one(port) for port in ports))
	return sorted(hits, key=lambda item: item.port)
