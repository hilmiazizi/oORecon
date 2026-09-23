"""oORecon entrypoint."""

import sys

from ui.app import ReconApp


def main() -> None:
	domain = sys.argv[1] if len(sys.argv) > 1 else ""
	ReconApp(domain).run()


if __name__ == "__main__":
	main()
