from __future__ import annotations

import subprocess

import pytest

from v2rm.net.firewall import (
    BLOCKED,
    INACTIVE,
    OPEN,
    RESTRICTED,
    UNKNOWN,
    check_firewall,
    parse_iptables_input,
    parse_ufw_status,
)

PORTS = [10808, 10809]


def ufw_text(rules: str = "", default: str = "deny (incoming), allow (outgoing), disabled (routed)") -> str:
    return (
        "Status: active\n"
        "Logging: on (low)\n"
        f"Default: {default}\n"
        "New profiles: skip\n\n"
        "To                         Action      From\n"
        "--                         ------      ----\n"
        "22/tcp                     ALLOW IN    Anywhere\n"
        + rules
        + "22/tcp (v6)                ALLOW IN    Anywhere (v6)\n"
    )


UFW_INACTIVE = "Status: inactive\n"


class Machine:
    """A fake host: which tools exist and what they print."""

    def __init__(self, ufw=None, iptables=None):
        self.answers = {"ufw": ufw, "iptables": iptables}

    def which(self, name):
        return f"/usr/sbin/{name}" if self.answers.get(name) is not None else None

    def run(self, args, **kwargs):
        answer = self.answers[args[0]]
        if isinstance(answer, Exception):
            raise answer
        returncode, stdout = answer
        return subprocess.CompletedProcess(args, returncode, stdout, "")

    def check(self, ports=PORTS):
        return check_firewall(ports, runner=self.run, which=self.which)


# ---- ufw ----------------------------------------------------------------------------------------


def test_ufw_inactive_is_recognised():
    parsed = parse_ufw_status(UFW_INACTIVE)
    assert parsed is not None and not parsed.active


def test_ufw_not_ufw_output_is_not_parsed():
    assert parse_ufw_status("ERROR: You need to be root to run this script") is None
    assert parse_ufw_status("") is None


def test_ufw_rules_and_default_are_read():
    parsed = parse_ufw_status(ufw_text("10808,10809/tcp            ALLOW IN    172.16.0.0/12\n"))
    assert parsed is not None and parsed.active
    assert parsed.default_incoming == "deny"
    assert len(parsed.rules) == 2  # 22/tcp and the proxy rule; the (v6) line is dropped
    proxy_rule = parsed.rules[1]
    assert proxy_rule.ports == ((10808, 10808), (10809, 10809))
    assert proxy_rule.proto == "tcp" and proxy_rule.allow and proxy_rule.source == "172.16.0.0/12"


def test_ufw_allowing_the_docker_subnets_is_restricted():
    report = Machine(ufw=(0, ufw_text("10808,10809/tcp            ALLOW IN    172.16.0.0/12\n"))).check()
    assert (report.tool, report.state) == ("ufw", RESTRICTED)
    assert report.detail == "ufw allows ports 10808 and 10809 only from 172.16.0.0/12"


def test_ufw_allowing_anywhere_is_open():
    report = Machine(ufw=(0, ufw_text("10808,10809/tcp            ALLOW IN    Anywhere\n"))).check()
    assert report.state == OPEN
    assert "from anywhere" in report.detail


def test_ufw_default_deny_with_no_rule_is_blocked():
    report = Machine(ufw=(0, ufw_text())).check()
    assert report.state == BLOCKED
    assert "default for incoming is deny" in report.detail


def test_ufw_default_allow_with_no_rule_is_open():
    report = Machine(ufw=(0, ufw_text(default="allow (incoming), allow (outgoing), disabled (routed)"))).check()
    assert report.state == OPEN


def test_ufw_port_ranges_are_understood():
    report = Machine(ufw=(0, ufw_text("10800:10810/tcp           ALLOW IN    172.16.0.0/12\n"))).check()
    assert report.state == RESTRICTED


def test_ufw_first_matching_rule_wins():
    rules = "10808,10809/tcp            DENY IN     Anywhere\n10808,10809/tcp            ALLOW IN    Anywhere\n"
    assert Machine(ufw=(0, ufw_text(rules))).check().state == BLOCKED


def test_ufw_ipv6_rules_do_not_open_the_ipv4_proxy():
    rules = "10808,10809/tcp (v6)       ALLOW IN    Anywhere (v6)\n"
    assert Machine(ufw=(0, ufw_text(rules))).check().state == BLOCKED


def test_ufw_routed_rules_are_ignored():
    rules = "10808,10809/tcp            ALLOW FWD   Anywhere\n"
    assert Machine(ufw=(0, ufw_text(rules))).check().state == BLOCKED


def test_ufw_rule_with_an_interface_qualifier_on_the_source():
    rules = "10808,10809/tcp            ALLOW IN    172.17.0.0/16 on docker0\n"
    report = Machine(ufw=(0, ufw_text(rules))).check()
    assert report.state == RESTRICTED
    assert report.detail == "ufw allows ports 10808 and 10809 only from 172.17.0.0/16 on docker0"


def test_ufw_allow_in_on_docker0_is_restricted_not_blocked():
    # `ufw allow in on docker0 to any port 10808,10809 proto tcp` lists the
    # interface in the To column -- the obvious rule for this setup must not be
    # misread as "nothing allows it".
    rules = "10808,10809/tcp on docker0  ALLOW IN    Anywhere\n"
    report = Machine(ufw=(0, ufw_text(rules))).check()
    assert report.state == RESTRICTED
    assert report.detail == "ufw allows ports 10808 and 10809 only from anywhere on docker0"


def test_ufw_deny_on_one_interface_does_not_block_the_others():
    rules = "10808,10809/tcp on eth0    DENY IN     Anywhere\n10808,10809/tcp on docker0  ALLOW IN    Anywhere\n"
    assert Machine(ufw=(0, ufw_text(rules))).check().state == RESTRICTED


def test_ufw_rule_for_a_specific_destination_address():
    rules = "172.17.0.1 10809/tcp        ALLOW IN    172.16.0.0/12\n"
    report = Machine(ufw=(0, ufw_text(rules))).check([10809])
    assert report.state == RESTRICTED


def test_ufw_application_profiles_are_skipped_not_misread():
    rules = "Nginx Full                 ALLOW IN    Anywhere\n"
    assert Machine(ufw=(0, ufw_text(rules))).check().state == BLOCKED


def test_ufw_mixed_ports_report_the_most_open_state_and_both_details():
    rules = "10808/tcp                  ALLOW IN    172.16.0.0/12\n"
    report = Machine(ufw=(0, ufw_text(rules))).check()
    assert report.state == RESTRICTED
    assert "port 10808" in report.detail and "port 10809" in report.detail


def test_ufw_without_root_is_unknown_not_a_guess():
    report = Machine(ufw=(1, "ERROR: You need to be root to run this script\n")).check()
    assert (report.tool, report.state) == ("ufw", UNKNOWN)
    assert "needs root" in report.detail


def test_ufw_active_without_a_default_policy_and_without_a_matching_rule_is_unknown():
    text = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n"
    assert Machine(ufw=(0, text)).check().state == UNKNOWN


# ---- iptables ---------------------------------------------------------------------------------------


def test_iptables_accept_policy_and_no_rules_is_open():
    report = Machine(iptables=(0, "-P INPUT ACCEPT\n")).check()
    assert (report.tool, report.state) == ("iptables", OPEN)


def test_iptables_drop_policy_with_a_subnet_rule_is_restricted():
    text = (
        "-P INPUT DROP\n"
        "-A INPUT -i lo -j ACCEPT\n"
        "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
        "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n"
        "-A INPUT -s 172.16.0.0/12 -p tcp -m multiport --dports 10808,10809 -j ACCEPT\n"
    )
    report = Machine(iptables=(0, text)).check()
    assert report.state == RESTRICTED
    assert report.detail == "iptables accepts ports 10808 and 10809 only from 172.16.0.0/12"


def test_iptables_drop_policy_without_a_rule_is_blocked():
    text = "-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n"
    assert Machine(iptables=(0, text)).check().state == BLOCKED


def test_iptables_rule_for_anyone_is_open():
    text = "-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 10808 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 10809 -j ACCEPT\n"
    assert Machine(iptables=(0, text)).check().state == OPEN


def test_iptables_state_new_rules_count_but_established_only_rules_do_not():
    new = "-P INPUT DROP\n-A INPUT -p tcp -m state --state NEW -m tcp --dport 10809 -j ACCEPT\n"
    assert Machine(iptables=(0, new)).check([10809]).state == OPEN
    established = "-P INPUT DROP\n-A INPUT -p tcp -m state --state ESTABLISHED,RELATED --dport 10809 -j ACCEPT\n"
    assert Machine(iptables=(0, established)).check([10809]).state == BLOCKED


def test_iptables_explicit_drop_before_accept():
    text = "-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 10808 -j DROP\n"
    assert Machine(iptables=(0, text)).check([10808]).state == BLOCKED


def test_iptables_comments_are_ignored():
    text = '-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 10808 -m comment --comment "v2rm socks" -j ACCEPT\n'
    assert Machine(iptables=(0, text)).check([10808]).state == OPEN


@pytest.mark.parametrize(
    "text",
    [
        "-P INPUT ACCEPT\n-A INPUT -j ufw-before-input\n",  # jumps to another chain
        "-P INPUT DROP\n-A INPUT -i eth0 -p tcp -m tcp --dport 10809 -j ACCEPT\n",  # interface-specific
        "-P INPUT DROP\n-A INPUT -m recent --update -j DROP\n",  # a module we don't model
        "-P INPUT DROP\n-A INPUT ! -s 10.0.0.0/8 -j DROP\n",  # negation
        "garbage\n",
        "",
    ],
)
def test_iptables_anything_not_understood_is_unknown(text):
    assert parse_iptables_input(text) is None
    report = Machine(iptables=(0, text)).check()
    assert (report.tool, report.state) == ("iptables", UNKNOWN)


def test_iptables_without_root_is_unknown():
    report = Machine(iptables=(1, "iptables v1.8.7: can't initialize iptables table `filter': Permission denied\n")).check()
    assert report.state == UNKNOWN and "needs root" in report.detail


# ---- combining the tools -------------------------------------------------------------------------------


def test_inactive_ufw_falls_through_to_iptables():
    report = Machine(ufw=(0, UFW_INACTIVE), iptables=(0, "-P INPUT DROP\n")).check()
    assert (report.tool, report.state) == ("iptables", BLOCKED)


def test_inactive_ufw_and_unreadable_iptables_is_unknown_and_says_why():
    report = Machine(ufw=(0, UFW_INACTIVE), iptables=(1, "Permission denied")).check()
    assert report.state == UNKNOWN
    assert report.detail.startswith("ufw is inactive, and iptables")


def test_inactive_ufw_alone_is_inactive():
    report = Machine(ufw=(0, UFW_INACTIVE)).check()
    assert (report.tool, report.state) == ("ufw", INACTIVE)


def test_active_ufw_takes_precedence_over_iptables():
    report = Machine(ufw=(0, ufw_text()), iptables=(0, "-P INPUT ACCEPT\n")).check()
    assert report.tool == "ufw" and report.state == BLOCKED


def test_no_tools_at_all_is_unknown():
    report = Machine().check()
    assert (report.tool, report.state) == (None, UNKNOWN)
    assert "no ufw or iptables" in report.detail


def test_a_tool_that_cannot_be_run_is_unknown():
    assert Machine(ufw=FileNotFoundError("ufw")).check().state == UNKNOWN
    assert Machine(iptables=subprocess.TimeoutExpired("iptables", 10)).check().state == UNKNOWN


def test_the_real_commands_are_the_ones_asked_for():
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, UFW_INACTIVE if args[0] == "ufw" else "-P INPUT ACCEPT\n", "")

    check_firewall(PORTS, runner=run, which=lambda name: name)
    assert calls == [["ufw", "status", "verbose"], ["iptables", "-S", "INPUT"]]
