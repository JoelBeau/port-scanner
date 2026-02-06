# Socket Scout

A high-performance, concurrent port scanner written in Python that focuses on correct asynchronous design, per-host isolation, and extensibility. This project demonstrates systems-oriented software engineering with an asyncio-based pipeline for efficient multi-host and large-range scanning.

## Notice
   - This project is designed to run on Linux, macOS, and Windows systems with Python 3.8 or later installed.
   - **Root/sudo privileges required:** SYN scanning and raw socket operations require elevated privileges on Linux/WSL/macOS
   - This project is a work in progress, and I am open to suggestions for improvement. Please let me know if you have any ideas or feedback.
   - **Ethical Use**: This tool is intended for educational purposes and for use on systems you own or have explicit permission to test. Unauthorized scanning of networks or systems may be illegal or unethical.

## Devices Supported
   - Linux distributions (Ubuntu, Debian, Fedora, etc.)
   - Windows 10 (WSL) or later
   - macOS

## Dependencies

### System Requirements
   - Python 3.8 or later
   - libpcap library (required for packet manipulation)
   
   **Install libpcap:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libpcap-dev
   
   # Fedora/RHEL
   sudo dnf install libpcap-devel
   
   # macOS (usually pre-installed, or via Homebrew)
   brew install libpcap
   ```

### Python Packages
   - See `pyproject.toml` for Python package dependencies (automatically installed with pip)

## Installation

**Note:** Due to PEP 668 (externally managed environments), it's recommended to use `pipx` for CLI tools or install in a virtual environment.

### Recommended: Using pipx
   ```bash
   # Install pipx if you don't have it
   sudo apt install pipx
   pipx ensurepath
   
   # Install socketscout
   pipx install socketscout
   
   # Run with sudo (required for SYN scanning)
   sudo ~/.local/bin/socketscout -t localhost
   ```

### Alternative: From PyPI with pip
   ```bash
   # Create a virtual environment
   python3 -m venv ~/socketscout-env
   source ~/socketscout-env/bin/activate
   pip install socketscout
   
   # Run with sudo
   sudo ~/socketscout-env/bin/socketscout -t localhost
   ```

### From GitHub Release
   ```bash
   # In a virtual environment
   python3 -m venv ~/socketscout-env
   source ~/socketscout-env/bin/activate
   pip install https://github.com/JoelBeau/socketscout/releases/latest/download/socketscout-1.0.2-py3-none-any.whl
   ```

### From Source
   ```bash
   # Clone and install in development mode
   git clone https://github.com/JoelBeau/socketscout.git
   cd socketscout
   python3 -m venv venv
   source venv/bin/activate
   pip install -e .
   ```

## Optional: Shell Alias Setup

To avoid typing the full path with sudo each time, add an alias to your shell configuration:

**For pipx installation:**
```bash
# Add to ~/.bashrc or ~/.zshrc
echo "alias socketscout='sudo ~/.local/bin/socketscout'" >> ~/.bash_aliases
source ~/.bashrc
```

**For venv installation:**
```bash
# Add to ~/.bashrc or ~/.zshrc
echo "alias socketscout='sudo ~/socketscout-env/bin/socketscout'" >> ~/.bash_aliases
source ~/.bashrc
```

After setting up the alias, you can simply run:
```bash
socketscout -t localhost -p 80,443
```


## Features

   - Concurrent scanning across multiple hosts and large port ranges
   - Asyncio-based pipeline to maximize throughput and avoid blocking
   - Per-host state isolation to prevent cross-target interference
   - TCP connect scanning as the default method
   - Optional SYN-based scanning for reduced connection overhead
   - Modular banner-grabbing stage for service metadata extraction
   - Configurable timeouts, retries, and concurrency limits
   - Clean separation between scan logic, networking primitives, and output

## How to Use

**Note:** Use `sudo` for SYN scanning or when accessing raw sockets. TCP connect scans may work without sudo on some systems.

   1. Basic scan of a single host (default port range is 1-1025):

      ```bash
         sudo socketscout -t localhost
      ```

   2. Scan specific ports:

      ```bash
         sudo socketscout -t localhost -p 22,80,443
      ```

   3. Scan a port range:

      ```bash
         sudo socketscout -t localhost -p 1-1024
      ```
      
   4. Scan with banner grabbing & increased verbosity:

      ```bash
         sudo socketscout -t localhost -v 2 -b
      ```
      
   5. Output to text file (other formats are available):
      ```bash
         sudo socketscout -t localhost -o test.txt
      ```

   6. View all available options:

      ```bash
         sudo socketscout --help
      ```
## Output Examples

   - Default output format (text, to console):

      ```bash
         sudo socketscout -t localhost -p 22,80,443 -b
      ```

      ![Example of text output format to console](https://bit.ly/text-output)

   - JSON output format to console:

      ```bash
         sudo socketscout -t localhost -p 22,80,443 -b -o json
      ```

      ![Example of JSON output format to console](https://bit.ly/json-output)
   
   - CSV output format to console:

      ```bash
         sudo socketscout -t localhost -p 22,80,443 -b -o csv
      ```
      
      ![Example of CSV output format to console](https://bit.ly/csv-output)


   For each output type, they can be written to a file instead of the console by providing a filename instead of "json" or "text" to the `-o` flag. For example:

   ```bash
      sudo socketscout -t localhost -p 22,80,443 -b -o results.txt
   ```

   Note that the file will be renamed by adding on the hostname (if applicable) to the end of the filename, so the above command will actually write to `results-localhost.txt`. This is to prevent overwriting results when scanning multiple hosts.

## Usage Examples

### Programmatic Usage

You can also import and use the scanner in your own Python scripts:

   ```python
      import asyncio
      from port_scanner import Scanner

      async def main():

         flags = {
            "scan_type": "tcp",
            "target": "example.com",
            "ports": [80, 443]
         }

         scanner = SCANNER_CLASS[flags["scan_type"]](**flags)
         results = await scanner.scan(**flags)
         for port in results:
            print(f"{port}")

      asyncio.run(main())
   ```

### Logging

The port scanner includes a centralized logging system that tracks all operations and events during scanning. 

**Location:** [port_scanner/log.py](port_scanner/log.py)

**Features:**
- File-based logging to `port_scanner.log`
- Configurable log directory via `port_scanner/config.py`
- Automatic log flushing on program exit
- Timestamp, logger name, and log level included in each message
- Default logging level: INFO

**Log Output:**
Logs are written to the configured log directory (typically `~/.config/port_scanner/logs/` or your custom `LOG_DIR` setting in config.py).

**Using the Logger in Your Code:**

```python
from port_scanner.log import setup_logger

# Create a logger for your module
logger = setup_logger(__name__)

# Log at different levels
logger.info("Scan started")
logger.warning("High latency detected")
logger.error("Connection timeout")
```

## Design Overview

This project is structured as a pipeline rather than a monolithic loop. Each target host maintains its own scanning state and concurrency limits, preventing shared-state bugs and ensuring predictable behavior when scanning multiple hosts concurrently.

Scanning is performed asynchronously using non-blocking I/O. Blocking operations are isolated from the event loop to preserve responsiveness and correctness. Banner grabbing is implemented as a separate stage that executes only after a port is confirmed open, reducing unnecessary connections and improving overall efficiency.

```
Input → Host Queue → Scanner Pipeline → Port Check → Banner Grab → Output
                          ↓
                    Per-Host State
                   (isolation, limits)
```

## Architecture & Components

The port scanner is organized into modular components, each responsible for a specific aspect of the scanning pipeline:

### `core/`
   - **scanner.py**: Main orchestration engine that manages the concurrent scanning pipeline across multiple hosts. Handles semaphore-based concurrency control, error handling, and per-host state isolation.
   - **output.py**: Formats and displays scan results in multiple formats (text, CSV, JSON) to console or file.

### `scanners/`
   - **base.py**: Abstract base class `Scan` defining the scanner interface. Implements shared functionality for banner grabbing across HTTP, SSH, and generic services.
   - **tcp.py**: `TCPConnect` implementation—establishes full TCP connections to test port availability. Default, reliable scanning method.
   - **syn.py**: `SYNScan` implementation—uses raw SYN packets for lower-overhead scanning. Requires elevated privileges.

### `models/`
   - **port.py**: `Port` data class representing scan results with service metadata (port number, state, banner info).
   - **arguments.py**: Argument validation and normalization for command-line flags.

### `utils/`
   - **network.py**: Network helper functions for IP/CIDR/hostname parsing, DNS resolution, and reachability checks.
   - **validation.py**: Input validation for ports, targets, and configuration parameters.

### `config.py` & `log.py`
   - **config.py**: Centralized configuration constants (timeouts, concurrency limits, log directories).
   - **log.py**: Logging setup with file-based output and configurable log levels.

**Component Interaction:**
```
CLI Input → models/arguments → utils/validation → core/scanner → scanners/{tcp,syn} → core/output
                ↓                                                                           ↓
           log.py ←──────────────────────────────────────────────────────────────────────→
```

## Scanning Modes

### TCP Connect Scan
   - Establishes a full TCP connection to determine port availability
   - Reliable and portable
   - Works without elevated privileges
   - Default scanning method

   ```python
      # Example: TCP connect scan
      flags = {
         "scan_type": "tcp",
         "target": "example.com",
         "ports": [80, 443]
      }

      scanner = SCANNER_CLASS[flags["scan_type"]](**flags)
      results = await scanner.scan(**flags)
   ```

### SYN Scan (Optional)
   - Sends crafted SYN packets using `Scapy` to infer port state
   - Lower overhead than full connections
   - Requires elevated privileges and packet-crafting support
   - Intended for controlled or lab environments

   ```python
      # Example: SYN connect scan
      flags = {
         "scan_type": "syn",
         "target": "example.com",
         "ports": [80, 443]
      }

      scanner = SCANNER_CLASS[flags["scan_type"]](**flags)
      results = await scanner.scan(**flags)
   ```

## Concurrency Model

   - Asynchronous task scheduling using asyncio
   - Global concurrency limits to control total in-flight operations
   - Per-host concurrency limits to isolate scan behavior
   - Non-blocking network operations throughout the pipeline

This design allows the scanner to scale efficiently while maintaining correctness under load.

   ```python
      # Configure concurrency limits in conf.py
      DEFAULT_CONCURRENCY_FOR_SCANS = 800
   ```


## Use Cases

   - Studying asynchronous programming and concurrency patterns in Python
   - Understanding network scanning tradeoffs and implementation details
   - Demonstrating systems-oriented software engineering skills
   - Exploring extensible security and networking tooling

## Contributing

   Suggestions are welcome! Please open an issue or submit a pull request.

## License

   MIT License - see LICENSE file for details
