import asyncio
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

from models import DnsInfo, DnsSection
from utils import dns_name


class DnsError(Exception):
	pass


# Keep DNS snappy — long lifetimes + serial types made the UI stall.
_QUERY_TIMEOUT = 2.0
_QUERY_LIFETIME = 3.5
_NAMESERVERS = ("1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4")
_TYPES = ("A", "AAAA", "NS", "MX", "SOA", "TXT")


def _resolver() -> dns.resolver.Resolver:
	resolver = dns.resolver.Resolver(configure=False)
	resolver.nameservers = list(_NAMESERVERS)
	resolver.timeout = _QUERY_TIMEOUT
	resolver.lifetime = _QUERY_LIFETIME
	# Modest EDNS buffer without DNSSEC DO bit (DO balloons some responses).
	try:
		resolver.use_edns(0, 0, 1232)
	except Exception:
		pass
	return resolver


def _resolve(resolver: dns.resolver.Resolver, domain: str, rdtype: str):
	"""Resolve one RR type. Soft-fail so one bad type does not kill the lookup."""
	try:
		answer = resolver.resolve(domain, rdtype, raise_on_no_answer=False, tcp=False)
	except dns.resolver.NXDOMAIN:
		return []
	except dns.exception.Timeout:
		return []
	except (
		dns.resolver.NoNameservers,
		dns.resolver.NoAnswer,
		dns.resolver.YXDOMAIN,
		dns.exception.DNSException,
	):
		# Truncation / UDP quirks only — one short TCP retry.
		try:
			answer = resolver.resolve(domain, rdtype, raise_on_no_answer=False, tcp=True)
		except (dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.exception.DNSException):
			return []
	if answer.rrset is None:
		return []
	return list(answer)


def _section_for(rdtype: str, records) -> DnsSection | None:
	if not records:
		return None
	if rdtype == "SOA":
		item = records[0]
		return DnsSection(
			"SOA",
			"Start of Authority",
			fields=(
				("Primary NS", dns_name(item.mname)),
				("Mailbox", dns_name(item.rname)),
				("Serial", str(item.serial)),
				("Refresh", str(item.refresh)),
				("Retry", str(item.retry)),
				("Expire", str(item.expire)),
				("Minimum TTL", str(item.minimum)),
			),
		)
	if rdtype == "NS":
		ns = sorted(dns_name(item.target) for item in records)
		return DnsSection("NS", "Nameservers", values=tuple(ns)) if ns else None
	if rdtype == "MX":
		mx_records = []
		for item in records:
			host = dns_name(item.exchange)
			mx_records.append((host, str(item.preference)))
		return (
			DnsSection("MX", "Mail Exchangers", records=tuple(mx_records))
			if mx_records
			else None
		)
	if rdtype == "TXT":
		txt = []
		for item in records:
			parts = []
			for part in item.strings:
				if isinstance(part, bytes):
					parts.append(part.decode("utf-8", "replace"))
				else:
					parts.append(str(part))
			joined = "".join(parts).strip()
			if joined:
				txt.append(joined)
		return DnsSection("TXT", "TXT Records", values=tuple(txt)) if txt else None
	if rdtype == "A":
		addresses = sorted(str(item) for item in records)
		return (
			DnsSection("A", "IPv4 Addresses", values=tuple(addresses))
			if addresses
			else None
		)
	if rdtype == "AAAA":
		v6 = sorted(str(item) for item in records)
		return DnsSection("AAAA", "IPv6 Addresses", values=tuple(v6)) if v6 else None
	return None


def _lookup(domain: str) -> DnsInfo:
	target = domain.lower().strip().rstrip(".")
	if not target or any(char in target for char in "/ \t"):
		raise DnsError("invalid domain")

	resolver = _resolver()

	def one(rdtype: str):
		return rdtype, _resolve(resolver, target, rdtype)

	# Parallel RR queries — wall time ≈ slowest type, not sum of all.
	sections: list[DnsSection] = []
	with ThreadPoolExecutor(max_workers=len(_TYPES)) as pool:
		results = list(pool.map(one, _TYPES))

	order = {name: index for index, name in enumerate(_TYPES)}
	for rdtype, records in sorted(results, key=lambda item: order[item[0]]):
		section = _section_for(rdtype, records)
		if section is not None:
			sections.append(section)

	if not sections:
		raise DnsError("Can't resolve " + domain)

	return DnsInfo(target, tuple(sections))


async def lookup(domain: str) -> DnsInfo:
	"""Query SOA, NS, MX, TXT, A, and AAAA from a public resolver."""
	return await asyncio.to_thread(_lookup, domain)
