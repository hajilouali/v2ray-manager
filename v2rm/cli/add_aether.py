"""`v2rm add aether`: a Cloudflare WARP connection through Aether (MASQUE over HTTP/3 or HTTP/2,
WireGuard, gool, gool-classic, MASQUE in MASQUE)."""

from __future__ import annotations

import contextlib
import os
import shutil
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from v2rm.engines.aether import files as aether_files
from v2rm.errors import V2rmError
from v2rm.models.aether import AetherMode, AetherSettings
from v2rm.models.profile import Profile
from v2rm.parsers.aether import build_profile
from v2rm.store.profiles import ProfileStore

console = Console()

MODES = ", ".join(m.value for m in AetherMode)


def parse_mode(value: str) -> AetherMode:
    try:
        return AetherMode(value.strip().lower())
    except ValueError:
        raise V2rmError(f"Unknown mode '{value}'. Choose one of: {MODES}") from None


def parse_env_pairs(pairs: list[str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key.strip():
            raise V2rmError(f"--env must look like AETHER_NAME=value, got {pair!r}")
        env[key.strip()] = value
    return env


def import_identity(profile: Profile, source: Path) -> Path:
    """Copy an identity file made by Aether itself (`aether.toml` from the command-line
    program, say) into the profile's folder under the name its mode reads it from. Only the
    first identity of the mode is brought in; any other is registered on first connect."""
    if not source.is_file():
        raise V2rmError(f"Identity file not found: {source}")
    head = source.read_text(encoding="utf-8", errors="replace")[:4096]
    if "device_id" not in head or "wg_private_key" not in head:
        raise V2rmError(f"{source} does not look like an Aether identity file (no device_id / wg_private_key)")
    assert profile.aether is not None
    base = aether_files.config_path(profile.id)
    target = aether_files.identity_files(base, profile.aether.mode)[0]
    target.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(target.parent, 0o700)
    shutil.copyfile(source, target)
    with contextlib.suppress(OSError):
        os.chmod(target, 0o600)  # it holds WARP private keys
    return target


def add_aether_profile(settings: AetherSettings, name: str = "", identity_file: Path | None = None) -> Profile:
    """Validate and store an Aether profile (a plain function: the menu calls it too)."""
    profile = build_profile(settings, name=name)
    if identity_file is not None and not identity_file.is_file():
        raise V2rmError(f"Identity file not found: {identity_file}")
    (stored,) = ProfileStore().add_many([profile])
    if identity_file is not None:
        try:
            import_identity(stored, identity_file)
        except V2rmError:
            ProfileStore().remove(stored.id)
            raise
    console.print(
        f"[green]+[/green] {escape(stored.name)} [dim](aether, {escape(stored.server_display)}, id {stored.id})[/dim]"
    )
    _print_hints(stored, imported=identity_file is not None)
    return stored


def _print_hints(profile: Profile, imported: bool) -> None:
    settings = profile.aether
    assert settings is not None
    if not imported:
        console.print(
            "  [dim]The first connection registers a free anonymous Cloudflare WARP device for it "
            "(`v2rm aether register` does that without connecting).[/dim]"
        )
    if settings.fragment and settings.transport != "h2":
        console.print(
            "  [dim]Fragmentation splits the TLS ClientHello of the HTTP/2 carrier and of the calls to the "
            "WARP API; add --transport h2 to use it on the tunnel itself.[/dim]"
        )


def add_aether_command(
    name: str | None = typer.Option(None, "--name", help="Display name (default: describes the mode)."),
    mode: str = typer.Option(
        "masque",
        "--mode",
        help=f"{MODES}. masque = WARP over MASQUE; wg = classic WireGuard; gool = WireGuard carried inside "
        "MASQUE (a foreign exit address); gool-classic = WireGuard in WireGuard (two hops); mim = MASQUE in MASQUE.",
    ),
    transport: str | None = typer.Option(
        None,
        "--transport",
        help="MASQUE carrier: h3 (QUIC over UDP, the default) or h2 (HTTP/2 over TCP, for networks that block or "
        "throttle UDP). Applies to masque, gool and mim.",
    ),
    h2: bool = typer.Option(False, "--h2", help="Shortcut for --transport h2."),
    h3: bool = typer.Option(False, "--h3", help="Shortcut for --transport h3."),
    outer: str | None = typer.Option(
        None,
        "--outer",
        metavar="IP:PORT",
        help="Use this gateway instead of scanning for one (the port is required). For gool-classic and mim "
        "this is the outer hop, the one your network sees.",
    ),
    inner: str | None = typer.Option(
        None,
        "--inner",
        metavar="IP:PORT",
        help="The second hop of gool, gool-classic or mim (the scan finds it if you only name --outer).",
    ),
    h2_peer: str | None = typer.Option(None, "--h2-peer", metavar="IP:PORT", help="Gateway of the HTTP/2 carrier, if it differs."),
    scan: str | None = typer.Option(
        None, "--scan", help="turbo | balanced (default) | thorough | verified | ironclad -- how hard to look for a gateway."
    ),
    ip: str | None = typer.Option(None, "--ip", help="IP version to scan over: v4 (default), v6 or both."),
    noize: str | None = typer.Option(
        None,
        "--noize",
        help="Traffic obfuscation: off | light | firewall | balanced | gfw | aggressive. "
        "Aether's default is firewall for MASQUE and balanced for WireGuard/gool; try gfw when it does not get through.",
    ),
    fragment: bool = typer.Option(
        False,
        "--fragment",
        help="Fragment the TLS ClientHello (HTTP/2 carrier and the calls to the WARP API), for firewalls "
        "that reset a ClientHello whose server name ends in cloudflareclient.com.",
    ),
    fragment_size: str | None = typer.Option(None, "--fragment-size", help="Fragment size in bytes: N or A-B (default 8-16)."),
    fragment_delay: str | None = typer.Option(None, "--fragment-delay", help="Delay between fragments in ms: N or A-B (default 2-10)."),
    fragment_sni: bool = typer.Option(
        False,
        "--fragment-sni",
        help="Make the first split fall in the middle of the server name, so an SNI filter never sees it whole "
        "(an Aether setting that is not in its --help, read from its source).",
    ),
    sni: str | None = typer.Option(None, "--sni", help="Server name for the MASQUE handshakes (default www.cloudflare.com)."),
    ech: str | None = typer.Option(None, "--ech", help="Encrypted ClientHello: 'auto' (looked up) or a base64 config."),
    ech_dns: str | None = typer.Option(None, "--ech-dns", help="Resolver for --ech auto: udp://ip, tcp://ip or an https:// DoH URL."),
    ech_domain: str | None = typer.Option(None, "--ech-domain", help="Domain whose ECH key --ech auto takes."),
    tls_ciphers: str | None = typer.Option(None, "--tls-ciphers", help="TLS 1.2 cipher suites, separated by ':'."),
    tls_groups: str | None = typer.Option(None, "--tls-groups", help="TLS groups in order, separated by ':'."),
    disable_grease: bool = typer.Option(False, "--disable-grease", help="Leave out the GREASE values Chrome's ClientHello carries."),
    no_quic_v2: bool = typer.Option(False, "--no-quic-v2", help="Don't send the QUIC v2 version-negotiation opener."),
    quick_reconnect: bool = typer.Option(
        True,
        "--quick-reconnect/--no-quick-reconnect",
        help="Try the gateways that worked last time before scanning again (masque, wg and gool modes).",
    ),
    reconnect_secs: int | None = typer.Option(None, "--reconnect-secs", help="Seconds to wait before reconnecting after a drop (default 2)."),
    startup_secs: int | None = typer.Option(None, "--startup-secs", help="Seconds a MASQUE tunnel gets to come up (default 30)."),
    validate_secs: int | None = typer.Option(None, "--validate-secs", help="Seconds to wait for the data-plane check (default 10)."),
    no_data_check: bool = typer.Option(False, "--no-data-check", help="Skip the end-to-end data-plane check."),
    keepalive: int | None = typer.Option(None, "--keepalive", help="WireGuard persistent keepalive in seconds (default 5)."),
    dns: list[str] = typer.Option([], "--dns", help="Resolver used inside the tunnel. Repeatable (default 1.1.1.1, 1.0.0.1)."),
    upstream: str | None = typer.Option(
        None,
        "--upstream",
        metavar="URL",
        help="Dial out through a proxy already running on this machine: socks5://127.0.0.1:1080 or "
        "http://user:pass@host:8080 (an HTTP proxy carries TCP only, so the HTTP/2 carrier is used).",
    ),
    block: list[str] = typer.Option(
        [],
        "--block",
        metavar="RULE",
        help="Never let this reach the network: example.com | full:name | keyword:word | regexp:re | "
        "10.0.0.0/8 | ip:addr | port:25 | private. Repeatable.",
    ),
    direct: list[str] = typer.Option([], "--direct", metavar="RULE", help="Send this straight out, bypassing the tunnel (same rule forms). Repeatable."),
    no_sniff: bool = typer.Option(
        False,
        "--no-sniff",
        help="Don't read the server name from the first bytes of a connection (on by default: it is what makes "
        "domain rules work for clients that only send an address, e.g. behind a tun front end).",
    ),
    sniff_ms: int | None = typer.Option(None, "--sniff-ms", help="How long to wait for those bytes (default 400)."),
    wait: int | None = typer.Option(
        None,
        "--wait",
        help="Seconds v2rm waits for the proxy to come up when connecting (default 120): Aether scans for a gateway first, "
        "which can take longer on a heavily filtered network.",
    ),
    exit_loc: str | None = typer.Option(None, "--exit-loc", help="Refuse a tunnel whose exit country is wrong: '!IR,RU' blocks those, 'DE,SE' allows only those."),
    exit_loc_secs: int | None = typer.Option(None, "--exit-loc-secs", help="How often to recheck the exit country (default 60)."),
    mark: str | None = typer.Option(None, "--mark", help="Linux firewall mark (SO_MARK) for Aether's own sockets, e.g. 0xff."),
    api_address: str | None = typer.Option(None, "--api-address", help="Where the WARP API calls go: ip|name[:port]."),
    perf: str | None = typer.Option(None, "--perf", help="Resource profile: low | medium | high."),
    stats: bool = typer.Option(False, "--stats", help="Log how much has gone through the tunnel."),
    log_level: str | None = typer.Option(None, "--log-level", help="error | warn | info (default) | debug | trace."),
    env: list[str] = typer.Option(
        [], "--env", metavar="AETHER_NAME=value", help="Pass any other AETHER_* setting to Aether (Zero Trust, Tor, Psiphon, ...). Repeatable."
    ),
    identity_file: Path | None = typer.Option(
        None,
        "--identity-file",
        help="Use a WARP identity Aether already made (its aether.toml) instead of registering a new device.",
    ),
) -> None:
    """Add a Cloudflare WARP connection through Aether (MASQUE HTTP/3 or HTTP/2, WireGuard, gool, ...)."""
    if h2 and h3:
        raise V2rmError("Use either --h2 or --h3, not both.")
    if (h2 or h3) and transport:
        raise V2rmError("Use either --transport or --h2/--h3, not both.")
    chosen = "h2" if h2 else "h3" if h3 else (transport or "")

    settings = AetherSettings(
        mode=parse_mode(mode),
        transport=chosen.lower(),
        outer=(outer or "").strip(),
        inner=(inner or "").strip(),
        h2_peer=(h2_peer or "").strip(),
        scan=(scan or "").strip(),
        ip=(ip or "").strip(),
        noize=(noize or "").strip(),
        fragment=fragment,
        fragment_size=(fragment_size or "").strip(),
        fragment_delay=(fragment_delay or "").strip(),
        fragment_sni=fragment_sni,
        sni=(sni or "").strip(),
        ech=(ech or "").strip(),
        ech_dns=(ech_dns or "").strip(),
        ech_domain=(ech_domain or "").strip(),
        tls_ciphers=(tls_ciphers or "").strip(),
        tls_groups=(tls_groups or "").strip(),
        disable_grease=disable_grease,
        quic_v2=not no_quic_v2,
        quick_reconnect=quick_reconnect,
        reconnect_secs=reconnect_secs,
        startup_secs=startup_secs,
        validate_secs=validate_secs,
        no_data_check=no_data_check,
        keepalive=keepalive,
        dns=[d.strip() for d in dns if d.strip()],
        upstream=(upstream or "").strip(),
        route_block=[r.strip() for r in block if r.strip()],
        route_direct=[r.strip() for r in direct if r.strip()],
        route_sniff=not no_sniff,
        route_sniff_ms=sniff_ms,
        wait_secs=wait,
        exit_loc=(exit_loc or "").strip(),
        exit_loc_secs=exit_loc_secs,
        mark=(mark or "").strip(),
        api_address=(api_address or "").strip(),
        perf=(perf or "").strip(),
        stats=stats,
        log_level=(log_level or "").strip(),
        env=parse_env_pairs(list(env)),
    )
    add_aether_profile(settings, name or "", identity_file)
