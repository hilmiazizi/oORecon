"""Render helpers for DNS boards and subdomain rows."""

import re

from rich.style import Style
from rich.text import Text

from models import DnsInfo, HostResult

# Full URL token. The terminal's own matcher stops early on long values and on & ? = ( ).
_URL = re.compile(r"https?://[^\s]+")

def dns_value_style(kind: str) -> str:
	if kind in {"A", "AAAA", "NS", "MX"}:
		return "bold cyan"
	if kind == "SOA":
		return "cyan"
	return ""


def dns_board(info: DnsInfo) -> Text:
	board = Text()
	label_width = 14
	sections = sorted(
		info.sections,
		key=lambda section: { "A": 0, "AAAA": 1 }.get(section.kind, 2),
	)
	for index, section in enumerate(sections):
		if index:
			board.append("\n")
		board.append(section.kind + "\n", style="bold cyan")
		if section.title:
			board.append(section.title + "\n", style="bold")
		board.append("─" * 48 + "\n", style="dim")
		if section.fields:
			for label, value in section.fields:
				board.append(label.ljust(label_width), style="bold")
				if label == "Primary NS":
					board.append(value + "\n", style="bold cyan")
				else:
					board.append(value + "\n")
		elif section.records:
			for host, priority in section.records:
				if host and priority:
					shown = priority + "  " + host
				else:
					shown = host or priority
				board.append(shown + "\n", style=dns_value_style(section.kind))
		else:
			for value in section.values:
				board.append(value + "\n", style=dns_value_style(section.kind))
	if not info.sections:
		board.append("No DNS records", style="dim")
	return board


def _linked(url: str) -> Text:
	"""Show a URL without letting the terminal matcher grab a cropped prefix.

	A zero-width space breaks the visible ``https://`` so Ctrl+click follows the
	OSC 8 target, which is the full URL, including query strings and ``()``.
	"""
	scheme, _, rest = url.partition("://")
	shown = Text(scheme + ":\u200b//" + rest)
	shown.stylize(Style(link=url))
	return shown


def link_text(url: str) -> Text:
	"""Cell text. Ctrl+click opens the full URL even when the column crops it."""
	if url.startswith(("http://", "https://")):
		return _linked(url)
	return Text(url)


def linkify(message: str, style: str = "") -> Text:
	"""Log or modal text. URLs inside the line keep a full Ctrl+click target."""
	text = Text("", style=style) if style else Text()
	last = 0
	for match in _URL.finditer(message):
		url = match.group(0).rstrip(".,;")
		text.append(message[last:match.start()])
		text.append(_linked(url))
		last = match.start() + len(url)
	text.append(message[last:])
	return text


def status_text(result: HostResult) -> Text:
	if not result.status:
		return Text("Down", style="bold red")
	style = {
		"1": "magenta",
		"2": "bold green",
		"3": "cyan",
		"4": "yellow",
		"5": "bold magenta",
	}.get(result.status[0], "white")
	return Text(result.status, style=style)


def cloudflare_text(result: HostResult) -> Text:
	if result.cloudflare:
		return Text("yes", style="bold orange1")
	return Text("no", style="dim")
