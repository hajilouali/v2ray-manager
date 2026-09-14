from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RouteRule:
    """One bypass/block rule: traffic matching ANY of the populated criteria
    below is routed to `kind` instead of the proxy.

    Domain-type criteria (domain_suffix/domain_keyword/geosite) and ip-type
    criteria (ip_cidr/geoip) may both be set here for convenience when
    authoring a preset, but engine generators must emit each populated list
    as its own native rule object rather than merging them: both Xray-core
    and sing-box AND together distinct condition *categories* within a
    single native rule, so merging would silently turn an intended "OR"
    (e.g. "Iranian domain OR Iranian IP") into an "AND" that almost never
    fires.
    """

    kind: str  # "direct" | "block"
    domain_suffix: list[str] = field(default_factory=list)
    domain_keyword: list[str] = field(default_factory=list)
    geosite: list[str] = field(default_factory=list)
    ip_cidr: list[str] = field(default_factory=list)
    geoip: list[str] = field(default_factory=list)

    def has_domain_criteria(self) -> bool:
        return bool(self.domain_suffix or self.domain_keyword or self.geosite)

    def has_ip_criteria(self) -> bool:
        return bool(self.ip_cidr or self.geoip)


@dataclass
class RoutePlan:
    name: str
    rules: list[RouteRule] = field(default_factory=list)
