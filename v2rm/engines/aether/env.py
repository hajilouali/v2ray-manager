"""The environment an Aether process is started with.

Every Aether flag has an `AETHER_*` environment variable, and a flag only wins over it. v2rm
passes everything through the environment: unlike a command line, it is not readable by every
user on the machine, which matters for an upstream proxy's password or a Zero Trust token.

The mapping is complete for what an Aether profile can say, and deliberately explicit about the
choices Aether would otherwise ask about on a terminal (protocol, scan mode, IP version, HTTP/3
or HTTP/2), so a run never depends on what Aether defaults to.
"""

from __future__ import annotations

from pathlib import Path

from v2rm.models.aether import MASQUE_MODES, UDP_ONLY_MODES, AetherMode, AetherSettings
from v2rm.net.proxy_url import ProxyEndpoint, redact

# Aether reads these even if v2rm never sets them, so a stray one in the user's shell must not
# change how a profile behaves. All AETHER_* variables and RUST_LOG are dropped from the
# environment a child inherits, then the profile's own are set.
INHERITED_PREFIX = "AETHER_"
INHERITED_EXTRA = ("RUST_LOG",)

_SECRET_WORDS = ("SECRET", "TOKEN", "PASSWORD", "PASS")


def scrubbed_environment(base: dict[str, str]) -> dict[str, str]:
    """`base` without the variables that would reconfigure Aether behind the profile's back."""
    return {
        key: value
        for key, value in base.items()
        if not key.upper().startswith(INHERITED_PREFIX) and key.upper() not in INHERITED_EXTRA
    }


def effective_transport(
    settings: AetherSettings, upstream: ProxyEndpoint | None, chained: bool, notes: list[str]
) -> str:
    """"h3", "h2", or "" when the mode has no choice (WireGuard is UDP only)."""
    if settings.mode in UDP_ONLY_MODES:
        return ""
    chosen = settings.transport.lower()
    if chosen:
        return chosen
    if upstream is not None and not upstream.is_socks:
        notes.append(
            "Using the HTTP/2 (TCP) carrier: an HTTP proxy in front of Aether can't carry the UDP "
            "that HTTP/3 needs."
        )
        return "h2"
    if chained:
        notes.append(
            "Using the HTTP/2 (TCP) carrier through the previous hop of the chain, which carries "
            "TCP reliably and UDP only if its server allows it. Set the transport to h3 to force QUIC."
        )
        return "h2"
    return "h3"


def build_environment(
    settings: AetherSettings,
    *,
    config_path: Path,
    socks: str,
    http: str | None = None,
    upstream: ProxyEndpoint | None = None,
    chained: bool = False,
    notes: list[str] | None = None,
) -> dict[str, str]:
    """The AETHER_* variables for one run.

    `socks` / `http` are `host:port` to listen on; `config_path` is the identity base file
    (Aether derives its other identity and cache files beside it); `upstream` is the proxy to
    dial through, whether the profile's own or the previous hop of a chain (`chained`)."""
    if notes is None:
        notes = []
    mode = settings.mode
    env: dict[str, str] = {
        "AETHER_CONFIG": str(config_path),
        "AETHER_SOCKS": socks,
    }
    if http:
        env["AETHER_HTTP_PROXY"] = http

    env["AETHER_PROTOCOL"] = "gool" if mode in (AetherMode.GOOL, AetherMode.GOOL_CLASSIC) else mode.value
    if mode == AetherMode.GOOL_CLASSIC:
        env["AETHER_GOOL_MODE"] = "classic"

    # The carrier of the MASQUE-based modes.
    transport = effective_transport(settings, upstream, chained, notes)
    if transport == "h2":
        env["AETHER_MASQUE_HTTP2"] = "1"
    elif transport == "h3":
        env["AETHER_MASQUE_HTTP2"] = "0"
    if mode in MASQUE_MODES and not settings.quic_v2:
        env["AETHER_QUIC_V2"] = "0"
    if settings.h2_peer:
        env["AETHER_MASQUE_H2_PEER"] = settings.h2_peer

    _gateways(settings, env)

    # How to look for a gateway, and whether to try the last working ones first.
    env["AETHER_SCAN"] = settings.scan.lower() or "balanced"
    env["AETHER_IP"] = settings.ip.lower() or "v4"
    env["AETHER_QUICK_RECONNECT"] = "1" if settings.quick_reconnect else "0"
    if settings.quick_reconnect and mode in (AetherMode.GOOL_CLASSIC, AetherMode.MIM):
        notes.append(
            f"Aether remembers the last working gateway only for the masque, wg and gool modes; "
            f"{mode.value} scans again after a restart. Pin its two hops (outer/inner) to skip the scan."
        )

    if settings.noize:
        env["AETHER_NOIZE"] = settings.noize.lower()

    if settings.fragment:
        env["AETHER_MASQUE_H2_FRAGMENT"] = "1"
        if settings.fragment_size:
            env["AETHER_MASQUE_H2_FRAGMENT_SIZE"] = settings.fragment_size
        if settings.fragment_delay:
            env["AETHER_MASQUE_H2_FRAGMENT_DELAY"] = settings.fragment_delay
        if transport != "h2":
            notes.append(
                "Fragmentation splits the TLS ClientHello of the HTTP/2 carrier and of the calls to the WARP "
                "API; the tunnel itself is not fragmented on this carrier (the noize profile obfuscates it)."
            )

    # TLS.
    for key, value in (
        ("AETHER_MASQUE_SNI", settings.sni),
        ("AETHER_ECH", settings.ech),
        ("AETHER_ECH_DNS", settings.ech_dns),
        ("AETHER_ECH_DOMAIN", settings.ech_domain),
        ("AETHER_TLS_CIPHERS", settings.tls_ciphers),
        ("AETHER_TLS_GROUPS", settings.tls_groups),
    ):
        if value:
            env[key] = value
    if settings.disable_grease:
        env["AETHER_DISABLE_GREASE"] = "1"

    # Timers and checks.
    if settings.reconnect_secs:
        env["AETHER_MASQUE_RECONNECT_SECS"] = env["AETHER_WG_RECONNECT_SECS"] = str(settings.reconnect_secs)
    if settings.startup_secs:
        env["AETHER_MASQUE_STARTUP_SECS"] = str(settings.startup_secs)
    if settings.validate_secs:
        env["AETHER_MASQUE_VALIDATE_SECS"] = env["AETHER_WG_VALIDATE_SECS"] = str(settings.validate_secs)
    if settings.no_data_check:
        env["AETHER_MASQUE_NO_DATA_CHECK"] = env["AETHER_WG_NO_DATA_CHECK"] = "1"
    if settings.keepalive:
        env["AETHER_WG_KEEPALIVE"] = str(settings.keepalive)
    if settings.dns:
        env["AETHER_DNS"] = ",".join(settings.dns)

    if upstream is not None:
        env["AETHER_UPSTREAM"] = upstream.url()

    # Routing: one rule per line (a regular expression may hold characters Aether would also
    # take for a separator elsewhere, so lines are the one separator we write).
    if settings.route_block:
        env["AETHER_ROUTE_BLOCK"] = "\n".join(r.strip() for r in settings.route_block)
    if settings.route_direct:
        env["AETHER_ROUTE_DIRECT"] = "\n".join(r.strip() for r in settings.route_direct)
    if not settings.route_sniff:
        env["AETHER_ROUTE_SNIFF"] = "0"
    if settings.route_sniff_ms:
        env["AETHER_ROUTE_SNIFF_MS"] = str(settings.route_sniff_ms)

    if settings.exit_loc:
        env["AETHER_EXIT_LOC"] = settings.exit_loc
    if settings.exit_loc_secs:
        env["AETHER_EXIT_LOC_SECS"] = str(settings.exit_loc_secs)
    if settings.mark:
        env["AETHER_MARK"] = settings.mark
    if settings.api_address:
        env["AETHER_API_ADDRESS"] = settings.api_address
    if settings.perf:
        env["AETHER_PERF_PROFILE"] = settings.perf.lower()
    if settings.stats:
        env["AETHER_STATS"] = "1"
    env["AETHER_LOG_LEVEL"] = settings.log_level.lower() or "info"

    # Anything else the user passed through: applied last, never over what v2rm owns.
    for key, value in settings.env.items():
        if key not in _OWNED:
            env[key] = value
    return env


# Mirrors v2rm.parsers.aether.OWNED_ENV without importing the parser here.
_OWNED = frozenset(
    {
        "AETHER_SOCKS",
        "AETHER_HTTP_PROXY",
        "AETHER_UPSTREAM",
        "AETHER_CONFIG",
        "AETHER_WG_CONFIG",
        "AETHER_MASQUE_CONFIG",
        "AETHER_REGISTER",
    }
)


def _gateways(settings: AetherSettings, env: dict[str, str]) -> None:
    """Gateways named by hand. What `outer` and `inner` mean depends on the mode."""
    outer, inner = settings.outer, settings.inner
    mode = settings.mode
    if mode == AetherMode.MASQUE and outer:
        env["AETHER_PEER"] = outer
    elif mode == AetherMode.WG and outer:
        env["AETHER_WG_PEER"] = outer
    elif mode == AetherMode.GOOL:
        # Gool over MASQUE: the MASQUE gateway, and the WireGuard endpoint dialled inside it.
        if outer:
            env["AETHER_PEER"] = outer
        if inner:
            env["AETHER_GOOL_INNER"] = inner
    elif mode == AetherMode.GOOL_CLASSIC:
        if outer:
            env["AETHER_WIW_OUTER_PEER"] = outer
        if inner:
            env["AETHER_WIW_INNER_PEER"] = inner
    elif mode == AetherMode.MIM:
        if outer:
            env["AETHER_MIM_OUTER_PEER"] = outer
        if inner:
            env["AETHER_MIM_INNER_PEER"] = inner


def describe_environment(env: dict[str, str]) -> list[str]:
    """`KEY=value` lines for showing to a person: secrets and proxy passwords hidden."""
    lines = []
    for key in sorted(env):
        value = env[key]
        if any(word in key for word in _SECRET_WORDS):
            value = "***"
        else:
            value = redact(value)
        lines.append(f"{key}={value!r}" if "\n" in value else f"{key}={value}")
    return lines
