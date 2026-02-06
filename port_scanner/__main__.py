"""Entry point for running the port scanner as a module.

Allows running the scanner with: python -m port_scanner
"""
import sys
from port_scanner.cli import main


if __name__ == "__main__":
    sys.exit(main())