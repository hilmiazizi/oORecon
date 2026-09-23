"""Render helpers for DNS boards and subdomain rows."""

from rich.text import Text

from models import DnsInfo, HostResult

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
