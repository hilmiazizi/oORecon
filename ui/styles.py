"""Textual CSS for the main recon dashboard."""

APP_CSS = """
#home {
	height: 1fr;
	width: 100%;
	align: center middle;
}
#home-panel {
	width: 64;
	height: auto;
	align: center top;
}
#banner {
	width: 100%;
	height: 6;
	content-align: center middle;
}
#tagline {
	width: 100%;
	height: 1;
	margin-top: 1;
	color: $text-muted;
	content-align: center middle;
}
#form {
	width: 100%;
	height: auto;
	margin-top: 2;
	padding: 1 2;
	background: $surface;
	border-left: tall $accent;
}
#domain {
	width: 100%;
}
#lookup {
	width: 100%;
	margin-top: 1;
}
#home-message {
	height: 1;
	margin-top: 1;
	color: $warning;
	content-align: center middle;
}
#home-hint {
	width: 100%;
	height: 1;
	margin-top: 1;
	color: $text-muted;
	content-align: center middle;
}
#results {
	display: none;
	height: 1fr;
	width: 100%;
}
#result-bar {
	height: 3;
	padding: 0 1;
}
#result-domain {
	width: 1fr;
	height: 3;
	content-align: left middle;
	text-style: bold;
}
#result-status {
	width: auto;
	height: 3;
	content-align: right middle;
	color: $text-muted;
	padding-right: 1;
}
#back {
	width: 12;
}
#results-body {
	height: 1fr;
}
#menu {
	height: 7fr;
}
#menu Tabs {
	width: 100%;
	height: 4;
}
#menu Tabs #tabs-list-bar,
#menu Tabs #tabs-list {
	width: 100%;
}
#menu Tabs Tab {
	width: 1fr;
	height: 3;
	padding: 0 1;
	text-align: center;
	content-align: center middle;
	text-style: bold;
	color: $text-muted;
	background: $surface;
}
#menu Tabs Tab:hover {
	color: $text;
	background: $foreground 10%;
}
#menu Tabs Tab.-active {
	color: $text;
	background: $accent 25%;
	text-style: bold;
}
#log-panel {
	height: 3fr;
	border-top: solid $accent;
	background: $surface;
}
#log-title {
	height: 1;
	padding: 0 1;
	text-style: bold;
	color: $accent;
}
#log {
	height: 1fr;
	padding: 0 1 0 1;
	scrollbar-size-vertical: 1;
}
TabPane {
	height: 1fr;
}
#dns-stats, #stats, #stats-ports, #stats-reverse, #stats-leaked {
	height: 1;
	padding: 0 1;
	color: $text-muted;
}
#progress, #progress-ports {
	height: 1;
	margin: 0 1;
}
#filters {
	height: 3;
	padding: 0 1;
}
#filters Button {
	margin-right: 1;
	min-width: 8;
}
#host-filter {
	width: 1fr;
	margin-left: 1;
}
#dns-board {
	height: 1fr;
	padding: 0 1 1 1;
}
#dns-view {
	width: 100%;
	height: auto;
	padding: 1 1 0 1;
}
#table, #table-ports, #table-reverse, #table-leaked {
	height: 1fr;
}
"""
