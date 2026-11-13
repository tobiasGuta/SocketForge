"""On-demand public IP metadata. No lookups run during collection."""

import json
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from ipaddress import ip_address, ip_network
from socket import gethostbyaddr
from time import monotonic
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

DOCUMENTATION = tuple(
    map(
        ip_network,
        ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"),
    )
)
PRIVATE = tuple(
    map(ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
)
REGISTRIES = {
    "rdap.arin.net",
    "rdap.db.ripe.net",
    "rdap.apnic.net",
    "rdap.lacnic.net",
    "rdap.afrinic.net",
}
HOSTS = REGISTRIES | {"data.iana.org", "stat.ripe.net"}


def classify(host):
    address = ip_address(host.split("%")[0])
    address = getattr(address, "ipv4_mapped", None) or address
    if address.is_loopback:
        return address, "Loopback"
    if address.is_link_local:
        return address, "Link-local"
    if address.is_multicast:
        return address, "Multicast"
    if any(address in network for network in DOCUMENTATION):
        return address, "Documentation address"
    if any(address in network for network in PRIVATE):
        return address, "Private network"
    if not address.is_global or address.is_reserved or address.is_unspecified:
        return address, "Special-use address"
    return address, "Public address"


def _allowed(url):
    parts = urlsplit(url)
    return parts.scheme == "https" and parts.netloc in HOSTS


class Redirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _allowed(newurl):
            raise ValueError("Unexpected lookup redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _json(url):
    if not _allowed(url):
        raise ValueError("Unexpected lookup service")
    with build_opener(Redirect()).open(
        Request(url, headers={"Accept": "application/json, application/rdap+json"}),
        timeout=3,
    ) as response:
        data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("Lookup response exceeded its size limit")
    return json.loads(data)


def _ripe(endpoint, resource):
    return _json(
        f"https://stat.ripe.net/data/{endpoint}/data.json?"
        + urlencode({"resource": str(resource)})
    )["data"]


@lru_cache(maxsize=8)
def _bootstrap(version, _day):
    return _json(f"https://data.iana.org/rdap/ipv{version}.json")["services"]


def _rdap(address, day):
    matches = [
        (network.prefixlen, server)
        for ranges, servers in _bootstrap(address.version, day)
        for block in ranges
        if address in (network := ip_network(block))
        for server in servers
        if _allowed(server)
    ]
    if not matches:
        return ()
    server = max(matches)[1]
    data = _json(f"{server.rstrip('/')}/ip/{address}")
    names = [
        str(item[3])
        for entity in data.get("entities", [])
        if "registrant" in entity.get("roles", [])
        for item in (entity.get("vcardArray") or [None, []])[1]
        if item[0] in ("fn", "org") and isinstance(item[3], str)
    ]
    return (
        ("Registered organization", " · ".join(dict.fromkeys(names)) or "Unavailable"),
        (
            "Registration network",
            data.get("name") or data.get("handle") or "Unavailable",
        ),
        ("Registry country", data.get("country") or "Unavailable"),
        ("Registry source", urlsplit(server).hostname),
    )


def _routing(address):
    data = _ripe("network-info", address)
    names = []
    for number in data.get("asns", [])[:3]:
        asn = f"AS{int(number)}"
        holder = _attempt(lambda asn=asn: _ripe("as-overview", asn).get("holder"))
        names.append(f"{asn} · {holder}" if holder else asn)
    prefix = data.get("prefix")
    return (
        ("Routing network", "\n".join(names) or "Unavailable"),
        ("Announced prefix", prefix or "Unavailable"),
    )


def _location(address):
    data = _ripe("maxmind-geo-lite", address)
    locations = [
        item
        for result in data.get("located_resources", [])
        for item in result.get("locations", [])
    ]
    values = sorted({item["country"] for item in locations if item.get("country")})
    return (("Estimated country · GeoLite", ", ".join(values)),) if values else ()


def _attempt(operation):
    try:
        return operation()
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError):
        return None


@lru_cache(maxsize=256)
def _lookup(address, hour):
    with ThreadPoolExecutor(max_workers=4) as pool:
        rdap, routing, location, ptr = [
            pool.submit(_attempt, operation)
            for operation in (
                lambda: _rdap(address, hour // 24),
                lambda: _routing(address),
                lambda: _location(address),
                lambda: gethostbyaddr(str(address))[0],
            )
        ]
        return (
            *(rdap.result() or (("Registration", "Unavailable"),)),
            *(routing.result() or (("Routing network", "Unavailable"),)),
            *(location.result() or (("Estimated country · GeoLite", "Unavailable"),)),
            ("Reverse DNS", ptr.result() or "Unavailable"),
        )


def lookup(host):
    address, scope = classify(host)
    if scope != "Public address":
        return (("Address scope", scope),)
    return _lookup(address, int(monotonic() // 3600))
