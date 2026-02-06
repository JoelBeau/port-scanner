# Port Scanner

A high-performance, concurrent port scanner written in Python that focuses on correct asynchronous design, per-host isolation, and extensibility. This project demonstrates systems-oriented software engineering with an asyncio-based pipeline for efficient multi-host and large-range scanning.

## Notice
   - This project is designed to run on Linux, macOS, and Windows systems with Python 3.8 or later installed.
   - This project is a work in progress, and I am open to suggestions for improvement. Please let me know if you have any ideas or feedback.
   - **Ethical Use**: This tool is intended for educational purposes and for use on systems you own or have explicit permission to test. Unauthorized scanning of networks or systems may be illegal or unethical.

## Devices Supported
   - Linux distributions (Ubuntu, Debian, Fedora, etc.)
   - Windows 10 or later
   - macOS

## Dependencies
   - Python 3.8 or later
   - See `port_scanner/pyproject.toml` for Python package dependencies

## Installation

### From PyPI (Comming Soon)
   ```bash
      pip install port-scanner
   ```

### From Source
   ```bash
      git clone https://github.com/JoelBeau/port-scanner.git
      cd port-scanner
      pip install -e .
   ```

### From GitHub Release
   ```bash
      pip install https://github.com/JoelBeau/port-scanner/releases/download/v1.0.0/port_scanner-1.0.0-py3-none-any.whl
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

   1. Basic scan of a single host:

      ```bash
         port-scanner 192.168.1.1
      ```

   2. Scan specific ports:

      ```bash
         port-scanner 192.168.1.1 -p 80,443,8080
      ```

   3. Scan a port range:

      ```bash
         port-scanner 192.168.1.1 -p 1-1024
      ```

   4. Scan with custom timeout and threads:

      ```bash
         port-scanner 192.168.1.1 -p 1-10000 --timeout 2 --threads 100
      ```

   5. View all available options:

      ```bash
         port-scanner --help
      ```

## Usage Examples

### Programmatic Usage

You can also import and use the scanner in your own Python scripts:

   ```python
      import asyncio
      from port_scanner import Scanner

      async def main():
          scanner = Scanner(
              hosts=['192.168.1.1'],
              ports=range(1, 1025),
              timeout=3.0,
              max_concurrent=50
          )
          results = await scanner.scan()
          for host, ports in results.items():
              print(f"{host}: {ports}")

      asyncio.run(main())
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

## Scanning Modes

### TCP Connect Scan
   - Establishes a full TCP connection to determine port availability
   - Reliable and portable
   - Works without elevated privileges
   - Default scanning method

   ```python
      # Example: TCP connect scan
      scanner = Scanner(hosts=['example.com'], ports=[80, 443])
      results = await scanner.scan(method='tcp')
   ```

### SYN Scan (Optional)
   - Sends crafted SYN packets using `Scapy` to infer port state
   - Lower overhead than full connections
   - Requires elevated privileges and packet-crafting support
   - Intended for controlled or lab environments

   ```python
      # Example: SYN scan (requires root/admin)
      scanner = Scanner(hosts=['example.com'], ports=[80, 443])
      results = await scanner.scan(method='syn')
   ```

## Concurrency Model

   - Asynchronous task scheduling using asyncio
   - Global concurrency limits to control total in-flight operations
   - Per-host concurrency limits to isolate scan behavior
   - Non-blocking network operations throughout the pipeline

This design allows the scanner to scale efficiently while maintaining correctness under load.

   ```python
      # Configure concurrency limits
      scanner = Scanner(
          hosts=['192.168.1.1', '192.168.1.2'],
          ports=range(1, 65536),
          max_concurrent=200,        # Global limit
          per_host_concurrent=50     # Per-host limit
      )
   ```

## Use Cases

   - Studying asynchronous programming and concurrency patterns in Python
   - Understanding network scanning tradeoffs and implementation details
   - Demonstrating systems-oriented software engineering skills
   - Exploring extensible security and networking tooling

## Contributing

   Contributions are welcome! Please open an issue or submit a pull request.

## License

   MIT License - see LICENSE file for details