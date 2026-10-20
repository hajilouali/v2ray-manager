from __future__ import annotations

from typing import Any

from v2rm.constants import DEFAULT_LISTEN_ADDRESS
from v2rm.engines.versioning import check_core_requirements
from v2rm.errors import UnsupportedProtocolError
from v2rm.models.auth import ProxyAuth
from v2rm.models.enums import EngineKind, Protocol
from v2rm.models.profile import Profile
from v2rm.net.proxy_url import ProxyEndpoint
from v2rm.routing.model import RoutePlan

ENGINE_LABELS = {EngineKind.XRAY: "Xray-core", EngineKind.SINGBOX: "sing-box", EngineKind.AETHER: "Aether"}

# Kinds of profile that exactly one engine can run.
_REQUIRED_ENGINE = {
    Protocol.RAW_XRAY: EngineKind.XRAY,
    Protocol.MASQUE: EngineKind.XRAY,
    Protocol.HYSTERIA2: EngineKind.SINGBOX,
    Protocol.TUIC: EngineKind.SINGBOX,
    Protocol.AETHER: EngineKind.AETHER,
}


def generate_config(
    engine: EngineKind,
    profile: Profile,
    route_plan: RoutePlan,
    socks_port: int,
    http_port: int,
    listen_address: str = DEFAULT_LISTEN_ADDRESS,
    auth: ProxyAuth | None = None,
    notes: list[str] | None = None,
    upstream: ProxyEndpoint | None = None,
) -> dict[str, Any]:
    """The runtime JSON config for an Xray or sing-box profile. `upstream`, if given, is a proxy
    this profile's own connection to its server is dialled through (a hop of a chain)."""
    if engine == EngineKind.AETHER:
        raise UnsupportedProtocolError(
            "Aether is configured through its environment, not a config file; see v2rm.engines.aether.env"
        )
    if engine == EngineKind.XRAY:
        from v2rm.engines.xray.generate import generate_config as gen
    else:
        from v2rm.engines.singbox.generate import generate_config as gen
    return gen(
        profile,
        route_plan,
        socks_port,
        http_port,
        listen_address=listen_address,
        auth=auth,
        notes=notes,
        upstream=upstream,
    )


def supported_protocols(engine: EngineKind) -> frozenset[Protocol]:
    if engine == EngineKind.AETHER:
        return frozenset({Protocol.AETHER})
    if engine == EngineKind.XRAY:
        from v2rm.engines.xray.generate import SUPPORTED_PROTOCOLS
    else:
        from v2rm.engines.singbox.generate import SUPPORTED_PROTOCOLS
    return SUPPORTED_PROTOCOLS


def required_engine(protocol: Protocol) -> EngineKind | None:
    """The one engine that can run this kind of profile, or None if either can."""
    return _REQUIRED_ENGINE.get(protocol)


def engine_for_protocol(protocol: Protocol) -> EngineKind:
    """The engine to use for a protocol when the user has no preference: the
    one that's required, else Xray-core."""
    return required_engine(protocol) or EngineKind.XRAY


def resolve_engine(profile: Profile, preferred: EngineKind | None) -> tuple[EngineKind, str | None]:
    """Pick the engine for a profile, given the user's default (None = none).

    Profiles only one engine can run (raw/MASQUE -> Xray-core, Hysteria2/TUIC
    -> sing-box) get that engine regardless of the default, with a one-line
    note instead of a failure; the saved default is left alone."""
    needed = required_engine(profile.protocol)
    if needed is None:
        return preferred or EngineKind.XRAY, None
    if needed == EngineKind.AETHER:
        return needed, None  # nobody expects the default engine to run a WARP profile
    note = None
    if preferred is not None and preferred != needed:
        kind = "raw Xray" if profile.is_raw else profile.protocol.value
        note = (
            f"Using {ENGINE_LABELS[needed]} for this {kind} profile "
            f"({ENGINE_LABELS[preferred]} can't run it); your default engine is unchanged."
        )
    return needed, note


def needs_preflight(engine: EngineKind, profile: Profile) -> bool:
    """Whether to validate the generated config with `<core> run -test` first
    (Xray only): raw/MASQUE profiles and ones using newer-core-only features."""
    if engine != EngineKind.XRAY:
        return False
    from v2rm.engines.xray.generate import needs_preflight as xray_needs_preflight

    return xray_needs_preflight(profile)


def check_core_compat(engine: EngineKind, profile: Profile, installed_version: str | None) -> None:
    """Raise CoreTooOldError if the installed core is outside a raw profile's
    declared `version` range (only Xray configs carry one)."""
    if engine == EngineKind.XRAY and profile.is_raw:
        check_core_requirements(profile, installed_version)
