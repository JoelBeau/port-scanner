import sys
from port_scanner.errors import PortScannerError
from port_scanner.cli import main
from port_scanner import config as conf

def run():
    try:
        main()
    except PortScannerError as e:
        print(e)
        return conf.EXIT_FAILURE
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return conf.EXIT_FAILURE
    return conf.EXIT_SUCCESS

if __name__ == "__main__":
    sys.exit(run())