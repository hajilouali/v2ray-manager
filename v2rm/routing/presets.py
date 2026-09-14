from __future__ import annotations

from v2rm.models.enums import RoutePreset
from v2rm.routing.model import RoutePlan, RouteRule

GLOBAL = RoutePlan(name="global", rules=[])

# Direct-route Iranian domestic sites/IPs and private/LAN ranges; tunnel
# everything else. The pattern most relevant to this tool's likely users.
BYPASS_IR = RoutePlan(
    name="bypass-ir",
    rules=[
        RouteRule(kind="direct", geoip=["private"]),
        RouteRule(kind="direct", geosite=["category-ir"], geoip=["ir"]),
    ],
)

# Mirrors v2rayN's classic "bypass mainland China" default.
BYPASS_CN = RoutePlan(
    name="bypass-cn",
    rules=[
        RouteRule(kind="direct", geoip=["private", "cn"]),
        RouteRule(kind="direct", geosite=["cn"]),
    ],
)

_BUILTIN = {
    RoutePreset.GLOBAL: GLOBAL,
    RoutePreset.BYPASS_IR: BYPASS_IR,
    RoutePreset.BYPASS_CN: BYPASS_CN,
}


def get_builtin(preset: RoutePreset) -> RoutePlan:
    try:
        return _BUILTIN[preset]
    except KeyError:
        raise ValueError(f"'{preset.value}' is not a built-in preset") from None
