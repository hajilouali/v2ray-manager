"""Runtime config for raw Xray profiles.

The stored JSON is never run verbatim. A deep copy is made and only the
*inbounds* are rewritten, so v2rm's guarantees hold for configs written by
someone else:

* no TUN/dokodemo/tproxy/... inbound survives -- v2rm only ever serves a
  local SOCKS and HTTP proxy;
* the primary SOCKS/mixed inbound is bound to the address the user chose
  with `v2rm port set --listen` (never a hard-coded one -- sample configs omit
  `listen`, which makes Xray bind 0.0.0.0 behind the user's back) and to v2rm's
  SOCKS port; an HTTP inbound is added on v2rm's HTTP port;
* the optional proxy credentials apply to every inbound.

Everything else -- dns, outbounds, routing, policy, fakedns, observatory,
balancers, version, and unknown keys such as `__Credits__`/`remarks` (Go's
JSON decoder ignores unknown fields) -- is left exactly as written.
"""

from __future__ import annotations

import copy
from typing import Any

from v2rm.constants import DEFAULT_LISTEN_ADDRESS
from v2rm.models.auth import ProxyAuth
from v2rm.models.profile import Profile

KEPT_INBOUND_PROTOCOLS = ("socks", "http", "mixed")
_WILDCARD_OR_LOOPBACK = ("0.0.0.0", "::", "", "127.0.0.1", "::1")


def udp_associate_address(listen_address: str) -> str | None:
    """The address SOCKS5 UDP-associate replies should advertise (Xray's
    `settings.ip`): the listen address when it's a specific, non-loopback
    one, since clients on other hosts/containers can't use the default
    127.0.0.1. None when the default is already right (loopback) or can't be
    known (a wildcard)."""
    return None if listen_address in _WILDCARD_OR_LOOPBACK else listen_address


def account_settings(protocol: str, auth: ProxyAuth) -> dict[str, Any]:
    accounts = [{"user": auth.user, "pass": auth.password}]
    if protocol in ("socks", "mixed"):
        return {"auth": "password", "accounts": accounts}
    return {"accounts": accounts}


def _apply_auth(inbound: dict[str, Any], auth: ProxyAuth | None) -> None:
    if auth is None:
        return
    settings = inbound.setdefault("settings", {})
    settings.update(account_settings(str(inbound["protocol"]).lower(), auth))


def _new_inbound(
    tag: str, protocol: str, port: int, listen_address: str, auth: ProxyAuth | None, sniffing: Any
) -> dict[str, Any]:
    inbound: dict[str, Any] = {"tag": tag, "listen": listen_address, "port": port, "protocol": protocol}
    settings: dict[str, Any] = {"auth": "noauth", "udp": True} if protocol == "socks" else {}
    ip = udp_associate_address(listen_address)
    if protocol == "socks" and ip:
        settings["ip"] = ip
    inbound["settings"] = settings
    if sniffing is not None:
        inbound["sniffing"] = copy.deepcopy(sniffing)
    _apply_auth(inbound, auth)
    return inbound


def rewrite_inbounds(
    config: dict[str, Any],
    socks_port: int,
    http_port: int,
    listen_address: str,
    auth: ProxyAuth | None,
    notes: list[str],
) -> None:
    """Replace config['inbounds'] (and patch routing inboundTag lists) in place."""
    original = config.get("inbounds") or []
    kept: list[dict[str, Any]] = []
    dropped: list[str] = []
    for inbound in original:
        protocol = str(inbound.get("protocol", "")).lower()
        label = f"{protocol or '?'} '{inbound['tag']}'" if inbound.get("tag") else (protocol or "?")
        if protocol in KEPT_INBOUND_PROTOCOLS and not kept:
            kept.append(copy.deepcopy(inbound))
        elif protocol in KEPT_INBOUND_PROTOCOLS:
            dropped.append(f"extra proxy inbound {label}")
        else:
            dropped.append(label)
    if dropped:
        notes.append(
            "Dropped inbound(s) from the raw config: "
            + ", ".join(dropped)
            + ". v2rm only serves one local SOCKS and one local HTTP proxy."
        )

    if not kept:
        config["inbounds"] = [
            _new_inbound("socks-in", "socks", socks_port, listen_address, auth, {"enabled": True, "destOverride": ["http", "tls"]}),
            _new_inbound("http-in", "http", http_port, listen_address, auth, {"enabled": True, "destOverride": ["http", "tls"]}),
        ]
        return

    primary = kept[0]
    protocol = str(primary.get("protocol", "")).lower()
    tag = primary.get("tag") or "v2rm-in"
    primary["tag"] = tag
    primary["listen"] = listen_address  # always explicit: omitted `listen` means 0.0.0.0 in Xray

    settings = primary.setdefault("settings", {})
    if "ip" in settings:
        ip = udp_associate_address(listen_address)
        if ip:
            settings["ip"] = ip

    if protocol == "http":
        primary["port"] = http_port
        twin_protocol, twin_port = "socks", socks_port
    else:  # socks / mixed -> the SOCKS port; mixed also serves HTTP on it
        primary["port"] = socks_port
        twin_protocol, twin_port = "http", http_port
    _apply_auth(primary, auth)

    twin_tag = f"{tag}-{twin_protocol}"
    twin = _new_inbound(twin_tag, twin_protocol, twin_port, listen_address, auth, primary.get("sniffing"))
    config["inbounds"] = [primary, twin]

    # Rules that match the original inbound by tag must match the twin too,
    # or traffic arriving on v2rm's other port would skip them.
    for rule in (config.get("routing") or {}).get("rules") or []:
        tags = rule.get("inboundTag")
        if isinstance(tags, list) and tag in tags and twin_tag not in tags:
            tags.append(twin_tag)


def build_raw_runtime_config(
    profile: Profile,
    socks_port: int,
    http_port: int,
    listen_address: str = DEFAULT_LISTEN_ADDRESS,
    auth: ProxyAuth | None = None,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    config = copy.deepcopy(profile.raw_config or {})
    rewrite_inbounds(config, socks_port, http_port, listen_address, auth, notes if notes is not None else [])
    return config
