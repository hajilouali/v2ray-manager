"""Best-effort look at the host firewall for the proxy's ports (for `doctor`).

Reading firewall rules normally needs root, and plenty of setups (nftables,
firewalld, cloud security groups, Docker's own rules) aren't covered. So this
only answers "open", "restricted", "blocked" or "inactive" when it has actually
read rules it fully understands; everything else is "unknown" -- it never guesses.
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass

OPEN = "open"
RESTRICTED = "restricted"
BLOCKED = "blocked"
INACTIVE = "inactive"
UNKNOWN = "unknown"

_OPENNESS = {OPEN: 3, RESTRICTED: 2, BLOCKED: 1}

PortRanges = tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class FirewallReport:
    tool: str | None  # "ufw" / "iptables" / None if neither was usable
    state: str
    detail: str


@dataclass(frozen=True)
class Verdict:
    """What one tool says about one port. `detail` has a {ports} placeholder
    so identical verdicts for several ports can be reported once."""

    state: str  # OPEN / RESTRICTED / BLOCKED
    detail: str


def _port_ranges(spec: str) -> PortRanges | None:
    """'10808', '10808,10809', '10800:10810' -> ranges; None if it isn't a plain port list."""
    ranges: list[tuple[int, int]] = []
    for piece in spec.split(","):
        match = re.fullmatch(r"(\d+)(?::(\d+))?", piece.strip())
        if not match:
            return None
        low = int(match.group(1))
        ranges.append((low, int(match.group(2) or low)))
    return tuple(ranges)


def _covers(ranges: PortRanges | None, port: int) -> bool:
    return ranges is None or any(low <= port <= high for low, high in ranges)


# ---- ufw ------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class UfwRule:
    ports: PortRanges | None  # None: every port
    proto: str | None
    allow: bool
    source: str  # "Anywhere" or an address/subnet
    interface: str | None = None  # set by `ufw allow in on docker0 ...`


@dataclass(frozen=True)
class UfwStatus:
    active: bool
    default_incoming: str | None  # "allow" / "deny" / "reject", None if not shown
    rules: tuple[UfwRule, ...]


_UFW_DEFAULT = re.compile(r"Default:\s*(\w+)\s*\(incoming\)", re.IGNORECASE)
_UFW_ACTIONS = {"allow": True, "limit": True, "deny": False, "reject": False}


_ON_INTERFACE = re.compile(r"\s+on\s+(\S+)\s*$")


def _split_interface(column: str) -> tuple[str, str | None]:
    """'10808/tcp on docker0' -> ('10808/tcp', 'docker0')."""
    match = _ON_INTERFACE.search(column)
    if not match:
        return column.strip(), None
    return column[: match.start()].strip(), match.group(1)


def _parse_ufw_to(spec: str) -> tuple[PortRanges | None, str | None] | None:
    """The 'To' column (interface qualifier already removed) -> (port ranges or None for any,
    proto); None if it isn't a plain port spec (an application profile name, say)."""
    spec = spec.strip()
    if spec.lower() == "anywhere":
        return None, None
    parts = spec.split()
    if len(parts) == 2 and re.fullmatch(r"[0-9a-fA-F:.]+(/\d+)?", parts[0]):
        spec = parts[1]  # a rule with a destination address shows as "172.17.0.1 10809/tcp"
    port_part, _, proto = spec.partition("/")
    ranges = _port_ranges(port_part)
    if ranges is None:
        return None
    return ranges, (proto.lower() or None)


def parse_ufw_status(text: str) -> UfwStatus | None:
    """Parse `ufw status verbose`; None if the text isn't recognisable ufw output."""
    lines = text.splitlines()
    status_line = next((ln for ln in lines if ln.strip().lower().startswith("status:")), None)
    if status_line is None:
        return None
    if "inactive" in status_line.lower():
        return UfwStatus(active=False, default_incoming=None, rules=())

    match = _UFW_DEFAULT.search(text)
    default = match.group(1).lower() if match else None

    rules: list[UfwRule] = []
    in_table = False
    for line in lines:
        stripped = line.strip()
        if re.match(r"^-+\s+-+\s+-+", stripped):
            in_table = True
            continue
        if not in_table or not stripped:
            continue
        columns = re.split(r"\s{2,}", stripped)
        if len(columns) < 3:
            continue
        to, action, source = columns[0], columns[1].lower().split(), columns[2]
        if "(v6)" in to or "(v6)" in source:
            continue  # IPv4 only: the proxy's inbounds are IPv4 addresses
        if not action or action[0] not in _UFW_ACTIONS or any(w in ("fwd", "out") for w in action[1:]):
            continue  # routed / outgoing rules don't govern connections to this host
        to, to_interface = _split_interface(to)
        source, source_interface = _split_interface(source)
        parsed = _parse_ufw_to(to)
        if parsed is None:
            continue
        ports, proto = parsed
        rules.append(UfwRule(ports, proto, _UFW_ACTIONS[action[0]], source, to_interface or source_interface))
    return UfwStatus(active=True, default_incoming=default, rules=tuple(rules))


def _ufw_port_verdict(status: UfwStatus, port: int) -> Verdict | None:
    for rule in status.rules:  # ufw evaluates rules in the order shown
        if rule.proto not in (None, "tcp") or not _covers(rule.ports, port):
            continue
        if not rule.allow:
            if rule.interface:
                continue  # a deny on one interface (typically the public one) says nothing about the others
            return Verdict(BLOCKED, "ufw denies {ports}")
        anywhere = rule.source.lower() == "anywhere"
        if anywhere and not rule.interface:
            return Verdict(OPEN, "ufw allows {ports} from anywhere")
        origin = "anywhere" if anywhere else rule.source
        if rule.interface:
            origin += f" on {rule.interface}"
        return Verdict(RESTRICTED, f"ufw allows {{ports}} only from {origin}")
    if status.default_incoming in ("deny", "reject"):
        return Verdict(BLOCKED, f"no ufw rule allows {{ports}} and the default for incoming is {status.default_incoming}")
    if status.default_incoming == "allow":
        return Verdict(OPEN, "no ufw rule covers {ports} and the default for incoming is allow")
    return None


# ---- iptables ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class IptablesRule:
    proto: str | None
    source: str | None
    ports: PortRanges | None
    accept: bool


@dataclass(frozen=True)
class IptablesInput:
    policy: str  # "ACCEPT" / "DROP"
    rules: tuple[IptablesRule, ...]


_SKIP = "skip"
_TARGETS = {"ACCEPT": True, "DROP": False, "REJECT": False}


def _parse_iptables_rule(tokens: list[str]) -> IptablesRule | str | None:
    """One `-A INPUT ...` rule. The rule itself; "skip" for rules that can't affect a *new*
    incoming connection (loopback, established-only); None if it uses something this parser
    doesn't understand, which makes the whole answer "unknown"."""
    proto = source = target = None
    ports: PortRanges | None = None
    states: set[str] = set()
    loopback = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if tok in ("-p", "--protocol"):
            proto = nxt.lower()
        elif tok in ("-s", "--source"):
            source = nxt
        elif tok in ("--dport", "--dports", "--destination-port", "--destination-ports"):
            ports = _port_ranges(nxt)
            if ports is None:
                return None
        elif tok == "-m":
            if nxt not in ("tcp", "multiport", "comment", "state", "conntrack"):
                return None
        elif tok in ("--state", "--ctstate"):
            states = {s.upper() for s in nxt.split(",")}
        elif tok in ("--comment", "--reject-with"):
            pass
        elif tok in ("-i", "--in-interface"):
            if nxt != "lo":
                return None  # which interface traffic arrives on isn't known here
            loopback = True
        elif tok == "-j":
            target = nxt
        else:
            return None  # a flag or option this parser doesn't know (e.g. "!", "--syn")
        i += 2  # every option handled above takes exactly one argument
    if loopback or (states and "NEW" not in states):
        return _SKIP
    if target not in _TARGETS:
        return None
    return IptablesRule(proto, source, ports, _TARGETS[target])


def parse_iptables_input(text: str) -> IptablesInput | None:
    """Parse `iptables -S INPUT`; None if it isn't fully understood (jumps to other chains,
    unusual matches, interface-specific rules, ...)."""
    policy = None
    rules: list[IptablesRule] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            return None
        if tokens[:2] == ["-P", "INPUT"] and len(tokens) == 3:
            policy = tokens[2]
        elif tokens[:2] == ["-A", "INPUT"]:
            parsed = _parse_iptables_rule(tokens[2:])
            if parsed is None:
                return None
            if isinstance(parsed, IptablesRule):
                rules.append(parsed)
        elif tokens[0] != "-N":
            return None
    if policy not in ("ACCEPT", "DROP"):
        return None
    return IptablesInput(policy, tuple(rules))


def _iptables_port_verdict(table: IptablesInput, port: int) -> Verdict:
    for rule in table.rules:
        if rule.proto not in (None, "tcp", "all") or not _covers(rule.ports, port):
            continue
        if not rule.accept:
            return Verdict(BLOCKED, "iptables drops {ports}")
        if rule.source in (None, "0.0.0.0/0", "0.0.0.0"):
            return Verdict(OPEN, "iptables accepts {ports} from anywhere")
        return Verdict(RESTRICTED, f"iptables accepts {{ports}} only from {rule.source}")
    if table.policy == "DROP":
        return Verdict(BLOCKED, "no iptables rule accepts {ports} and the INPUT policy is DROP")
    return Verdict(OPEN, "nothing in iptables restricts {ports} (INPUT policy ACCEPT)")


# ---- putting it together ------------------------------------------------------------------------------


def _ports_label(ports: Sequence[int]) -> str:
    if len(ports) == 1:
        return f"port {ports[0]}"
    return "ports " + " and ".join(str(p) for p in ports)


def _summarise(tool: str, verdicts: dict[int, Verdict]) -> FirewallReport:
    distinct = {(v.state, v.detail) for v in verdicts.values()}
    if len(distinct) == 1:
        state, detail = next(iter(distinct))
        return FirewallReport(tool, state, detail.format(ports=_ports_label(list(verdicts))))
    state = max((v.state for v in verdicts.values()), key=_OPENNESS.__getitem__)
    return FirewallReport(tool, state, "; ".join(v.detail.format(ports=f"port {p}") for p, v in verdicts.items()))


def _read(runner: Callable[..., subprocess.CompletedProcess], args: list[str]) -> str | None:
    try:
        proc = runner(args, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout or ""


def check_firewall(
    ports: Sequence[int],
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
) -> FirewallReport:
    """What ufw/iptables say about incoming TCP on `ports`, or "unknown"."""
    ufw_inactive = False

    if which("ufw"):
        out = _read(runner, ["ufw", "status", "verbose"])
        status = parse_ufw_status(out) if out is not None else None
        if status is None:
            return FirewallReport("ufw", UNKNOWN, "ufw is installed but its rules couldn't be read (needs root)")
        if status.active:
            ufw_verdicts = {p: _ufw_port_verdict(status, p) for p in ports}
            if any(v is None for v in ufw_verdicts.values()):
                return FirewallReport("ufw", UNKNOWN, "ufw is active but its default policy couldn't be determined")
            return _summarise("ufw", {p: v for p, v in ufw_verdicts.items() if v is not None})
        ufw_inactive = True

    if which("iptables"):
        out = _read(runner, ["iptables", "-S", "INPUT"])
        if out is None:
            prefix = "ufw is inactive, and " if ufw_inactive else ""
            return FirewallReport("iptables", UNKNOWN, prefix + "iptables rules couldn't be read (needs root)")
        table = parse_iptables_input(out)
        if table is None:
            return FirewallReport(
                "iptables", UNKNOWN, "iptables INPUT rules are too involved to interpret (other chains, interfaces, ...)"
            )
        return _summarise("iptables", {p: _iptables_port_verdict(table, p) for p in ports})

    if ufw_inactive:
        return FirewallReport("ufw", INACTIVE, "ufw is installed but inactive, and there is no iptables command to check")
    return FirewallReport(None, UNKNOWN, "no ufw or iptables command found (nftables/firewalld rules are not checked)")
