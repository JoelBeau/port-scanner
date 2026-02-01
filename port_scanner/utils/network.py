import os
import ipaddress as ipa

# Ensure ip is reachable
def is_reachable(ip: str):
    output = os.popen(f"ping {ip} -c 4").read()
    return False if "0 received" in output else True

''' Normalize target into a list of IPs '''
def normalize_target(target):
    if isinstance(target, ipa.IPv4Network):
        return target.hosts()
    elif isinstance(target, range):
        return [ipa.IPv4Address(ip) for ip in target]
    return [target]


def is_excluded(ip: str, exclusions: list[str]):
    if not exclusions:
        return False
    return ip in exclusions
