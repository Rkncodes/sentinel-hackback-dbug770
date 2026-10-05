"""Canonical text form for IP addresses."""

import ipaddress


class InvalidIP(ValueError):
    pass


def canonical_ip(text) -> str:
    """Return the one canonical form of a single IP address, or raise InvalidIP.

    An IPv4 address written in IPv6-mapped form is the IPv4 address.
    Ranges, zone identifiers and anything else are rejected.
    """
    if not isinstance(text, str) or "%" in text:
        raise InvalidIP("ip is not a valid IP address")
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        raise InvalidIP("ip is not a valid IP address") from None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)
