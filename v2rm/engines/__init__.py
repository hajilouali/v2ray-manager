from __future__ import annotations

from typing import Any

from v2rm.constants import DEFAULT_LISTEN_ADDRESS
from v2rm.models.enums import EngineKind, Protocol
from v2rm.models.profile import Profile
from v2rm.routing.model import RoutePlan


def generate_config(
    engine: EngineKind,
    profile: Profile,
    route_plan: RoutePlan,
    socks_port: int,
    http_port: int,
    listen_address: str = DEFAULT_LISTEN_ADDRESS,
) -> dict[str, Any]:
    if engine == EngineKind.XRAY:
        from v2rm.engines.xray.generate import generate_config as gen
    else:
        from v2rm.engines.singbox.generate import generate_config as gen
    return gen(profile, route_plan, socks_port, http_port, listen_address=listen_address)


def supported_protocols(engine: EngineKind) -> frozenset[Protocol]:
    if engine == EngineKind.XRAY:
        from v2rm.engines.xray.generate import SUPPORTED_PROTOCOLS
    else:
        from v2rm.engines.singbox.generate import SUPPORTED_PROTOCOLS
    return SUPPORTED_PROTOCOLS


def engine_for_protocol(protocol: Protocol) -> EngineKind:
    """Pick a sensible default engine for a protocol: prefer Xray-core, fall
    back to sing-box for the protocols only it supports (hysteria2/tuic)."""
    from v2rm.engines.singbox.generate import SUPPORTED_PROTOCOLS as SINGBOX_PROTOCOLS
    from v2rm.engines.xray.generate import SUPPORTED_PROTOCOLS as XRAY_PROTOCOLS

    if protocol in XRAY_PROTOCOLS:
        return EngineKind.XRAY
    if protocol in SINGBOX_PROTOCOLS:
        return EngineKind.SINGBOX
    raise ValueError(f"No engine supports protocol '{protocol.value}'")
