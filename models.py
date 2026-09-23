"""Shared data models for oORecon tools and UI."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HostResult:
	host: str
	status: str | None
	ip: str | None = None
	cloudflare: bool = False


@dataclass(frozen=True)
class PortHit:
	host: str
	port: int
	banner: str
	raw_banner: str = ""
	service: str = ""
	state: str = "open"

	@property
	def summary(self) -> str:
		parts = [self.state]
		if self.service:
			parts.append(self.service)
		if self.banner:
			parts.append(self.banner[:80])
		return " · ".join(parts)


@dataclass(frozen=True)
class SitemapHit:
	kind: str
	url: str
	detail: str = ""


@dataclass(frozen=True)
class DirHit:
	path: str
	status: int
	length: int
	url: str


@dataclass(frozen=True)
class JsHit:
	kind: str
	value: str
	source: str = ""
	context: str = ""


@dataclass(frozen=True)
class ReverseIpHit:
	ip: str
	host: str


@dataclass(frozen=True)
class LeakedUrlHit:
	url: str
	kind: str
	occurrence: int = 1


@dataclass(frozen=True)
class DnsSection:
	kind: str
	title: str
	values: tuple[str, ...] = ()
	fields: tuple[tuple[str, str], ...] = ()
	records: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class DnsInfo:
	domain: str
	sections: tuple[DnsSection, ...]

	@property
	def ips(self) -> tuple[str, ...]:
		found = []
		for section in self.sections:
			if section.kind in {"A", "AAAA"}:
				found.extend(section.values)
		return tuple(found)

	@property
	def exposes_ip(self) -> bool:
		return bool(self.ips)

	def text(self) -> str:
		lines = []
		for section in self.sections:
			lines.append(section.kind)
			if section.title:
				lines.append(section.title)
			if section.fields:
				for label, value in section.fields:
					lines.append(label)
					lines.append(value)
			elif section.records:
				for host, priority in section.records:
					if host:
						lines.append(host)
					if priority:
						lines.append(priority)
			else:
				lines.extend(section.values)
		return "\n".join(lines)


@dataclass
class HostWorkspaceData:
	"""In-memory cache of per-host workspace tool results."""

	host: str
	sitemap: list[SitemapHit] = field(default_factory=list)
	directories: list[DirHit] = field(default_factory=list)
	jsminer: list[JsHit] = field(default_factory=list)
	stats: dict[str, str] = field(
		default_factory=lambda: {
			"sitemap": "",
			"directories": "",
			"jsminer": "",
		}
	)
	complete: bool = False


class HostCache:
	"""Session memory cache keyed by hostname."""

	def __init__(self) -> None:
		self._data: dict[str, HostWorkspaceData] = {}

	def __contains__(self, host: str) -> bool:
		return host.lower().rstrip(".") in self._data

	def get(self, host: str) -> HostWorkspaceData | None:
		return self._data.get(host.lower().rstrip("."))

	def ensure(self, host: str) -> HostWorkspaceData:
		key = host.lower().rstrip(".")
		item = self._data.get(key)
		if item is None:
			item = HostWorkspaceData(host=key)
			self._data[key] = item
		return item

	def put(self, data: HostWorkspaceData) -> None:
		self._data[data.host.lower().rstrip(".")] = data

	def clear(self) -> None:
		self._data.clear()
