# v2rm

[🇮🇷 مستندات فارسی](README.fa.md)

**v2rm** is a friendly command-line manager for [Xray-core](https://github.com/XTLS/Xray-core) and [sing-box](https://github.com/SagerNet/sing-box) on Linux. It brings the everyday workflow of v2rayN (the Windows GUI client) to the terminal: add configs from share links, subscribe to and refresh subscription URLs, edit configs, really test whether one works, and switch your active connection — all from one small tool.

**v2rm never touches system-wide proxy settings.** Connecting starts a local SOCKS5 + HTTP proxy on `127.0.0.1` and nothing else. Only the applications you explicitly point at that port use it; everything else on your machine keeps its normal, direct internet connection.

## Features

- **Add configs** from `vmess://`, `vless://` (including VLESS+REALITY), `trojan://`, `ss://` (SIP002 and legacy), `hysteria2://`/`hy2://`, and `tuic://` share links — one at a time, from a file, or piped in from stdin.
- **Subscriptions**: add a subscription URL and refresh it later. Auto-detects base64 link lists, plain link lists, and Clash/Mihomo YAML. Refreshing diffs the new list against what you have — it adds new nodes, drops ones that disappeared, and updates the rest in place, matching by server identity (not name) so a provider renaming a node doesn't create a duplicate or break your active connection.
- **Edit configs** in place, either with `--flag` options for common fields or by opening the full profile in `$EDITOR`.
- **Real connectivity testing**: `v2rm test` doesn't just ping a config — it spins up a throwaway instance of the engine, connects through it, and actually downloads a small file, reporting real latency and throughput. `test --all` does this for every saved profile in parallel and ranks the results.
- **Switch connections** in one command, live, with `v2rm connect <profile>` or `v2rm profile use <profile>`.
- **Local SOCKS + HTTP proxy only.** No TUN device, no system/NetworkManager proxy changes, ever. Use `v2rm env` to opt one shell session in (`eval "$(v2rm env)"`), or `v2rm exec -- <command>` to run a single command through it — nothing else is affected.
- **Two swappable engines** — Xray-core and sing-box — installed, updated, and switched with `v2rm core`. sing-box additionally covers Hysteria2 and TUIC, which Xray-core doesn't support.
- **Routing rules**: built-in `global` (proxy everything), `bypass-cn` (v2rayN's classic mainland-China bypass), and `bypass-ir` (direct-routes Iranian sites/IPs and LAN, tunnels everything else) presets, plus a hand-editable `custom` rule file.
- **A friendly interactive menu** (just run `v2rm`) for everyday use, backed by the exact same commands available on the command line for scripting.

## Install

Requires Python 3.10+ on Linux.

```bash
git clone https://github.com/hajilouali/v2ray-manager.git
cd v2ray-manager
./install.sh
```

`install.sh` installs [pipx](https://pipx.pypa.io/) first if it isn't already present, installs v2rm with it, and runs `pipx ensurepath` -- so `v2rm` ends up on `PATH` without any manual step. (Like any PATH change, it only takes effect in *new* shells -- the script tells you if you need to open one or `source` your shell's rc file.)

Prefer doing it by hand? `pipx install .` works the same way; `pip install --user .` also works but **won't** fix `PATH` for you -- if `v2rm` isn't found afterward, that's almost always why: pip puts the script in `~/.local/bin`, which isn't always on `PATH` by default, especially for `root`. Fix it with `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc`, or install system-wide instead with plain `pip install .`.

Then install at least one engine:

```bash
v2rm core install xray
# and/or
v2rm core install singbox
```

## Quick start

```bash
# Add a config from a share link
v2rm add "vless://uuid@host:443?security=reality&sni=example.com&pbk=...&sid=...&flow=xtls-rprx-vision#My Server"

# Or add a subscription
v2rm sub add "https://provider.example.com/sub/abc123" --name myprovider

# See what you have, and how fast each one really is
v2rm profile list
v2rm test --all

# Connect
v2rm connect "My Server"
v2rm status

# Point one app at it -- system-wide nothing changes
curl --socks5-hostname 127.0.0.1:10808 https://example.com
# or, for a whole shell session:
eval "$(v2rm env)"
curl https://example.com    # now goes through the proxy
exit                         # back to a normal shell

v2rm disconnect
```

Prefer a menu over remembering flags? Just run `v2rm` with no arguments.

## Command reference

| Command | Description |
|---|---|
| `v2rm` / `v2rm menu` | Launch the interactive menu |
| `v2rm add <link>` / `add -` / `add -f FILE` | Add config(s) from share link(s) |
| `v2rm connect [profile]` | Connect (or reconnect using the active profile) |
| `v2rm disconnect` | Disconnect |
| `v2rm status` | Show connection status |
| `v2rm test <profile>` | Real connectivity test: connect and download |
| `v2rm test --all [--protocol P] [--subscription S] [--concurrency N] [--timeout S]` | Test every profile, ranked by latency |
| `v2rm env [--shell sh\|fish]` | Print proxy env vars for one shell to `eval` |
| `v2rm exec -- <cmd...>` | Run one command with the proxy env injected |
| `v2rm export [file]` | Back up profiles/subscriptions/routes/state to a file |
| `v2rm import <file> [--replace]` | Restore from a backup file |
| `v2rm doctor` | Environment/engine/connection diagnostics |
| `v2rm profile list [--subscription S] [--protocol P]` | List profiles |
| `v2rm profile show <id> [--link]` | Show a profile, or re-print it as a share link |
| `v2rm profile edit <id> [--name ...] [--server ...] ...` | Edit fields; no flags opens `$EDITOR` |
| `v2rm profile remove <id> [--yes] [--force]` | Remove a profile |
| `v2rm profile rename <id> <name>` | Rename a profile |
| `v2rm profile use <id>` | Set the active profile (live-switches if connected) |
| `v2rm sub add <url> [--name] [--user-agent] [--proxy]` | Add a subscription |
| `v2rm sub update [id] [--all] [--proxy] [--force]` | Refresh subscription(s) |
| `v2rm sub remove <id> [--yes]` | Remove a subscription and its profiles |
| `v2rm sub list` / `sub show <id>` | List / inspect subscriptions |
| `v2rm route show [--preset P]` | Show the active (or a previewed) routing preset |
| `v2rm route set <global\|bypass-ir\|bypass-cn\|custom>` | Switch routing preset |
| `v2rm route edit` | Edit the custom routing rules file |
| `v2rm route update-data [--force]` | Refresh Xray-core's GeoIP/GeoSite data |
| `v2rm core list` | List installed engine versions |
| `v2rm core install <xray\|singbox> [--version V]` | Download and install an engine |
| `v2rm core update <xray\|singbox>` | Update to the latest release |
| `v2rm core use <xray\|singbox>` | Set the default engine |
| `v2rm core remove <xray\|singbox> [--version V] [--all]` | Remove installed engine version(s) |
| `v2rm port show` / `port set [--socks P] [--http P]` | View/change the local proxy ports |

Every command has `--help`.

## Routing presets

- **`global`** (default): everything sent to the proxy goes out through it. No bypass rules.
- **`bypass-ir`**: Iranian sites/IPs and private/LAN addresses go direct; everything else is tunneled.
- **`bypass-cn`**: the classic v2rayN default — mainland China and private/LAN addresses go direct.
- **`custom`**: `v2rm route edit` opens a commented YAML file (`~/.config/v2rm/routes/custom.yaml`) where you list `direct`/`block` rules by domain suffix, domain keyword, geosite category, IP range, or GeoIP code.

Process-based routing (matching by which app made the connection) isn't exposed as first-class commands — it overlaps with the whole point of the local SOCKS/HTTP design (you already choose which apps use the proxy), and it's fragile/platform-specific on Linux. Power users can still add `process_name`/`process_path` rules directly by hand-editing `custom.yaml` — sing-box supports them natively.

There's also no TUN/system-wide mode, by design — see the FAQ below.

## Engines: Xray-core vs sing-box

| Protocol | Xray-core | sing-box |
|---|---|---|
| VMess | ✅ | ✅ |
| VLESS (incl. REALITY) | ✅ | ✅ |
| Trojan | ✅ | ✅ |
| Shadowsocks | ✅ | ✅ |
| Hysteria2 | ❌ | ✅ |
| TUIC | ❌ | ✅ |

`v2rm connect` picks Xray-core by default and falls back to sing-box automatically for Hysteria2/TUIC profiles; override with `v2rm core use <engine>`.

## Configuration & data

All under standard XDG locations (overridable with `V2RM_CONFIG_HOME`/`V2RM_DATA_HOME`/`V2RM_STATE_HOME`/`V2RM_CACHE_HOME`):

- `~/.config/v2rm/` — profiles, subscriptions, app state, `routes/custom.yaml`
- `~/.local/share/v2rm/bin/` — installed engine binaries
- `~/.local/state/v2rm/run/` — the generated runtime config, pidfile, engine log
- `~/.cache/v2rm/assets/` — cached GeoIP/GeoSite data

## FAQ

**Why no system-wide proxy or TUN mode?** By design. v2rm only ever binds a local SOCKS/HTTP proxy; nothing on your system is redirected unless you explicitly point it there (`v2rm env`, `v2rm exec`, or your app's own proxy settings). If you want whole-system tunneling, this isn't the tool for that.

**Where do I get a config?** From whoever runs the server you're connecting to — a share link or a subscription URL.

## Development

```bash
pip install -e ".[dev]"
pytest
```

Everything except actually launching a real engine binary and hitting the real network (marked `integration`, skipped by default) runs offline and deterministically.

## License

MIT — see [LICENSE](LICENSE).
