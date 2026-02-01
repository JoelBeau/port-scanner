# Concurrent Python Port Scanner

A high-performance, concurrent port scanner written in Python.  
This project focuses on correct asynchronous design, per-host isolation, and extensibility rather than simple sequential scanning.

The scanner supports multi-host, large-range scans using an asyncio-based pipeline, with optional SYN-based probing and modular banner grabbing for service identification.

---

## Features

- Concurrent scanning across multiple hosts and large port ranges
- Asyncio-based pipeline to maximize throughput and avoid blocking
- Per-host state isolation to prevent cross-target interference
- TCP connect scanning as the default method
- Optional SYN-based scanning for reduced connection overhead
- Modular banner-grabbing stage for service metadata extraction
- Configurable timeouts, retries, and concurrency limits
- Clean separation between scan logic, networking primitives, and output

---

## Design Overview

This project is intentionally structured as a pipeline rather than a monolithic loop.

Each target host maintains its own scanning state and concurrency limits, preventing shared-state bugs and ensuring predictable behavior when scanning multiple hosts concurrently. Global concurrency is bounded to avoid overwhelming the system or network, while per-host limits prevent a single target from monopolizing resources.

Scanning is performed asynchronously using non-blocking I/O. Blocking operations (such as SYN probing with packet crafting) are isolated from the event loop to preserve responsiveness and correctness.

Banner grabbing is implemented as a separate stage that executes only after a port is confirmed open, reducing unnecessary connections and improving overall efficiency.

---

## Scanning Modes

### TCP Connect Scan
- Establishes a full TCP connection to determine port availability
- Reliable and portable
- Works without elevated privileges

### SYN Scan (Optional)
- Sends crafted SYN packets using ```Scapy``` to infer port state
- Lower overhead than full connections
- Requires elevated privileges and packet-crafting support
- Intended for controlled or lab environments

---

## Concurrency Model

- Asynchronous task scheduling using asyncio
- Global concurrency limits to control total in-flight operations
- Per-host concurrency limits to isolate scan behavior
- Non-blocking network operations throughout the pipeline

This design allows the scanner to scale efficiently while maintaining correctness under load.

---

## Use Cases

- Studying asynchronous programming and concurrency patterns in Python
- Understanding network scanning tradeoffs and implementation details
- Demonstrating systems-oriented software engineering skills
- Exploring extensible security and networking tooling

---

## Legal and Ethical Notice

This tool is intended for educational purposes and for use on systems you own or have explicit permission to test. Unauthorized scanning of networks or systems may be illegal or unethical.
