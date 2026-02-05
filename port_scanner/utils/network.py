"""Network operations and host/IP management utilities.

Provides functions for host reachability checking, target normalization,
and exclusion list handling.
"""
import os
import port_scanner.errors as errors
import subprocess
import ipaddress as ipa


def is_reachable(ip: str):
    """Check if a host is reachable via ping.

    Sends 4 ICMP ping packets to the target IP with a 5-second timeout.

    Args:
        ip (str): Target IP address to check.

    Returns:
        bool: True if host responds to ping.

    Raises:
        HostUnreachableError: If host does not respond or timeout occurs.
    """
    try:
        subprocess.run(
            ["ping", "-c", "4", str(ip)],
            check=False,
            text=False,
            timeout=5,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except (subprocess.TimeoutExpired, OSError):
        raise errors.HostUnreachableError(ip)


def normalize_target(target):
    """Normalize various target formats into a standard structure.

    Converts different input formats (single IP, network, range, hostname)
    into a tuple of (host_list, hostname).

    Args:
        target: Target specification (IPv4Address, IPv4Network, range, tuple, etc.).

    Returns:
        tuple: (host_list, hostname) where:
               - host_list: List or generator of IPv4Address objects
               - hostname: Resolved hostname or None
    """
    if isinstance(target, ipa.IPv4Network):
        return (target.hosts(), None)
    elif isinstance(target, range):
        return ([ipa.IPv4Address(ip) for ip in target], None)
    elif isinstance(target, tuple):
        return ([target[0]], target[1])
    else:
        return ([target], None)


def is_excluded(ip: str, exclusions: list[str]):
    """Check if an IP is in the exclusion list.

    Args:
        ip (str): IP address to check.
        exclusions (list[str]): List of IP addresses to exclude.

    Returns:
        bool: True if IP is in exclusions, False otherwise.
        """
    if not exclusions:
        return False
    return ip in exclusions
