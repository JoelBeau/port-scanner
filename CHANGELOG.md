# Changelog

All notable changes to SocketScout will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-02-06

### Fixed
- CLI command now displays clean error messages instead of Python tracebacks
- Refactored error handling to be consistent between `socketscout` command and `python -m port_scanner`

### Changed
- Moved error handling into `cli.py:main()` for more Pythonic structure
- Simplified `__main__.py` to be a minimal wrapper

### Documentation
- Added libpcap system dependency installation instructions
- Updated installation guide to recommend pipx for CLI tool installation
- Added alternative installation methods (venv, GitHub releases, from source)
- Documented shell alias setup for easier sudo usage
- Clarified when sudo privileges are required

## [1.0.0] - 2026-02-06

### Added
- Initial release of SocketScout (formerly port-scanner)
- Concurrent scanning across multiple hosts and large port ranges
- Asyncio-based pipeline for efficient scanning
- TCP connect scanning as default method
- Optional SYN-based scanning for reduced connection overhead
- Modular banner-grabbing stage for service metadata extraction
- Configurable timeouts, retries, and concurrency limits
- Multiple output formats (text, JSON, CSV)
- Output to console or file
- Comprehensive logging system
- Per-host state isolation to prevent cross-target interference

### Changed
- Renamed project from "port-scanner" to "SocketScout" to avoid PyPI name conflict
- Updated package name from `port-scanner` to `socketscout`
- Updated CLI command from `port-scanner` to `socketscout`

## [Unreleased]

### Added
- (Features planned for next release)

### Changed
- (Changes planned for next release)

### Fixed
- (Bug fixes planned for next release)

---

## Version History

- **v1.0.1** - Bug fix release: Clean error messages (February 6, 2026)
- **v1.0.0** - Initial PyPI release as SocketScout (February 6, 2026)
