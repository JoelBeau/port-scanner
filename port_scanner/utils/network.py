import os
import port_scanner.errors as errors
import subprocess
import ipaddress as ipa


# Ensure ip is reachable
def is_reachable(ip: str):
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
    """Normalize target into a list of IPs"""
    if isinstance(target, ipa.IPv4Network):
        return (target.hosts(), None)
    elif isinstance(target, range):
        return ([ipa.IPv4Address(ip) for ip in target], None)
    elif isinstance(target, tuple):
        return ([target[0]], target[1])
    else:
        return ([target], None)


def is_excluded(ip: str, exclusions: list[str]):
    if not exclusions:
        return False
    return ip in exclusions
