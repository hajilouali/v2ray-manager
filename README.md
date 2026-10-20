# v2rm

[🇮🇷 مستندات فارسی](README.fa.md)

**v2rm** is a friendly command-line manager for [Xray-core](https://github.com/XTLS/Xray-core), [sing-box](https://github.com/SagerNet/sing-box) and [Aether](https://github.com/CluvexStudio/Aether) (Cloudflare WARP over MASQUE, WireGuard and gool) on Linux. It brings the everyday workflow of v2rayN (the Windows GUI client) to the terminal: add configs from share links or complete Xray JSON files, subscribe to and refresh subscription URLs, edit configs, really test whether one works, and switch your active connection — all from one small tool.

**v2rm never touches system-wide proxy settings.** Connecting starts a local SOCKS5 + HTTP proxy on `127.0.0.1` (or on the address *you* choose with `v2rm port set --listen`) and nothing else. Only the applications you explicitly point at that port use it; everything else on your machine keeps its normal, direct internet connection.

## Features

- **Add configs** from `vmess://`, `vless://` (including VLESS+REALITY), `trojan://`, `ss://` (SIP002 and legacy), `hysteria2://`/`hy2://`, `tuic://` and `masque://` share links — one at a time, from a file, or piped in from stdin. Links can carry the newer Xray options too: `fp=unsafe`, `cs` (cipher suites), `ech`, `fm` (finalmask / TLS-hello fragmentation), XHTTP `mode`/`extra`, VLESS post-quantum `encryption`, `headers`, `packetEncoding` (see [Share-link options](#share-link-options)).
- **Complete Xray JSON configs ("raw" profiles)**: add a whole Xray config — a file, an array of them, or a JSON subscription — and v2rm runs it as written, replacing only its inbounds so v2rm's local-proxy guarantees still hold. See [Raw Xray JSON configs](#raw-xray-json-configs).
- **MASQUE (HTTP/2) profiles** for Xray-core: `v2rm add masque ...`. See [MASQUE](#masque-http2).
- **Aether (Cloudflare WARP) profiles**: MASQUE over **HTTP/3 or HTTP/2** (with TLS-ClientHello fragmentation), classic WireGuard, **gool** (WireGuard inside MASQUE), **gool-classic** (WireGuard in WireGuard, both hops found by scanning or named by hand) and MASQUE-in-MASQUE, with traffic obfuscation, routing rules by domain/address/port (the name is read from the TLS server name, so they work behind a tun front end too), an upstream proxy, and automatic / quick reconnect to the last gateway that worked. See [Aether](#aether-cloudflare-warp).
- **Chains**: string saved profiles together — `warp-then-vless`, `vless-then-warp`, even a proxy that is already running on this machine first — and use the chain like any other connection. See [Chains](#chains).
- **Subscriptions**: add a subscription URL and refresh it later. Auto-detects Xray JSON, plain link lists (including ones with `#profile-title` / `#profile-update-interval` header comments), base64 link lists, and Clash/Mihomo YAML. A `#name` at the end of the URL becomes the subscription's name and is never sent to the server. Refreshing diffs the new list against what you have — it adds new nodes, drops ones that disappeared, and updates the rest in place, matching by server identity (not name) so a provider renaming a node doesn't create a duplicate or break your active connection.
- **Edit configs** in place, either with `--flag` options for common fields or by opening the full profile (YAML, or the JSON config for a raw profile) in `$EDITOR`.
- **Real connectivity testing**: `v2rm test` doesn't just ping a config — it spins up a throwaway instance of the engine, connects through it, and actually downloads a small file, reporting real latency and throughput. `test --all` does this for every saved profile in parallel and ranks the results.
- **Switch connections** in one command, live, with `v2rm connect <profile>` or `v2rm profile use <profile>`.
- **Local SOCKS + HTTP proxy only.** No TUN device, no system/NetworkManager proxy changes, ever. Use `v2rm env` to opt one shell session in (`eval "$(v2rm env)"`), or `v2rm exec -- <command>` to run a single command through it — nothing else is affected.
- **You choose where it listens**: loopback (the default), a specific address, the Docker bridge (`--listen docker`) or every interface (`0.0.0.0`) — with an optional login (`--auth USER:PASS`), warnings when the proxy is reachable beyond localhost, and a `doctor` that looks at your firewall. See [Using v2rm from Docker](#using-v2rm-from-docker).
- **Three engines** — Xray-core and sing-box (swappable defaults), plus Aether for WARP profiles — installed, updated, and switched with `v2rm core`. sing-box additionally covers Hysteria2 and TUIC, which Xray-core doesn't support; Xray-core covers MASQUE, raw configs and the newer link options, which sing-box doesn't.
- **Routing rules**: built-in `global` (proxy everything), `bypass-cn` (v2rayN's classic mainland-China bypass), and `bypass-ir` (direct-routes Iranian sites/IPs and LAN, tunnels everything else) presets, plus a hand-editable `custom` rule file.
- **A friendly interactive menu** (just run `v2rm`) for everyday use — including "Add a JSON config", "Add a MASQUE server", "Add an Aether connection" and "Make a chain" — backed by the exact same commands available on the command line for scripting.

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
# for Cloudflare WARP profiles (Aether):
v2rm core install aether
```

Raw configs, MASQUE and several link options need a recent Xray-core. Xray-core currently publishes its newest builds only as GitHub *pre-releases*, which v2rm's installer skips unless you ask for them, so run `v2rm core update xray --pre` (a plain `core update xray` would give you the older stable release), then `v2rm doctor` to see exactly what your Xray supports.

`core install` and `core update` ask GitHub's API for the release, which allows only 60 anonymous requests an hour per IP address; a shared server or NAT can use that up. If you see "rate limit exceeded", wait for the reset time it prints, or export `GITHUB_TOKEN` (any token, even with no scopes, raises the limit to 5000 an hour). The token is only sent to the API, never with downloads.

## Quick start

```bash
# Add a config from a share link
v2rm add "vless://uuid@host:443?security=reality&sni=example.com&pbk=...&sid=...&flow=xtls-rprx-vision#My Server"

# ...or a complete Xray JSON config (one object, or an array of them)
v2rm add --json config.json
curl -s https://example.com/config.json | v2rm add --json -

# ...or a MASQUE server (HTTP/2)
v2rm add masque --server masque.example.com --sni front.example.com --user alice --pass 's3cret' --path /masque

# ...or a Cloudflare WARP connection through Aether (HTTP/2 carrier + ClientHello fragmentation)
v2rm add aether --name "WARP h2" --h2 --fragment

# ...or chain two of them: your traffic goes through WARP first, then out of your own server
v2rm chain add warp-then-server "WARP h2" "My Server"

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
| `v2rm add --json FILE` / `add --json -` | Add a complete Xray JSON config (an object, or an array of them) |
| `v2rm add masque --server H --sni S [--port P] [--alpn h2] [--user U --pass P] [--path /x] [--host H] [--header 'K: V' ...] [--fp chrome] [--name N]` | Add a MASQUE server |
| `v2rm add aether [--mode M] [--h2\|--h3] [--fragment] [--noize P] [--outer IP:PORT --inner IP:PORT] [--upstream URL] [--block R --direct R] ...` | Add a Cloudflare WARP connection through Aether (see [Aether](#aether-cloudflare-warp)) |
| `v2rm chain add <name> <hop> <hop> ...` / `chain list` / `chain show <name>` / `chain remove <name>` | Chain connections (see [Chains](#chains)) |
| `v2rm aether register <profile>` / `aether gateways <profile> [--forget]` / `aether env <profile>` | Register a WARP identity without connecting / see (and forget) the remembered gateways / show what Aether is given |
| `v2rm connect [profile]` | Connect (or reconnect using the active profile) |
| `v2rm disconnect` | Disconnect |
| `v2rm status` | Show connection status (profile type, listening?, login, routing) |
| `v2rm test <profile>` | Real connectivity test: connect and download |
| `v2rm test --all [--protocol P] [--subscription S] [--concurrency N] [--timeout S]` | Test every profile, ranked by latency |
| `v2rm env [--shell sh\|fish]` | Print proxy env vars for one shell to `eval` |
| `v2rm env --docker` / `env --host ADDR` | Print a `VAR=value` block for a container that reaches the proxy at the Docker bridge address / at ADDR |
| `v2rm exec -- <cmd...>` | Run one command with the proxy env injected |
| `v2rm export [file]` | Back up profiles (raw configs included)/subscriptions/routes/state to a file |
| `v2rm import <file> [--replace]` | Restore from a backup file |
| `v2rm doctor` | Environment/engine diagnostics: Xray version, MASQUE/finalmask support, whether `aether` runs, broken chains, geo data, who can reach the proxy, firewall |
| `v2rm profile list [--subscription S] [--protocol P]` | List profiles (Type column: `vless`, `trojan`, `masque`, `raw`, `aether`, `chain`, ...) |
| `v2rm profile show <id> [--link\|--json]` | Show a profile, re-print it as a share link, or print its stored data as JSON |
| `v2rm profile edit <id> [--name ...] [--server ...] ...` | Edit fields; no flags opens `$EDITOR` (the JSON config, for a raw profile) |
| `v2rm profile remove <id> [--yes] [--force]` | Remove a profile |
| `v2rm profile rename <id> <name>` | Rename a profile |
| `v2rm profile use <id>` | Set the active profile (live-switches if connected) |
| `v2rm sub add <url[#name]> [--name] [--user-agent] [--proxy]` | Add a subscription |
| `v2rm sub update [id] [--all] [--proxy] [--force] [--respect-interval]` | Refresh subscription(s) |
| `v2rm sub remove <id> [--yes]` | Remove a subscription and its profiles |
| `v2rm sub list` / `sub show <id>` | List / inspect subscriptions |
| `v2rm route show [--preset P]` | Show the active (or a previewed) routing preset |
| `v2rm route set <global\|bypass-ir\|bypass-cn\|custom>` | Switch routing preset |
| `v2rm route edit` | Edit the custom routing rules file |
| `v2rm route update-data [--force]` | Refresh Xray-core's GeoIP/GeoSite data |
| `v2rm core list` | List installed engine versions |
| `v2rm core install <xray\|singbox\|aether> [--version V \| --pre] [--variant musl\|gnu]` | Download, verify and install an engine (`--pre`: newest release even if it is a pre-release; `--variant`: Aether's static musl build (default) or its glibc build) |
| `v2rm core update <xray\|singbox\|aether> [--pre]` | Update to the latest release; never downgrades (`--pre` includes pre-releases) |
| `v2rm core use <xray\|singbox>` | Set the default engine (Aether only runs Aether profiles, so it is never the default) |
| `v2rm core remove <xray\|singbox\|aether> [--version V] [--all]` | Remove installed engine version(s) |
| `v2rm port show` | Show the listen address, ports and whether a login is required |
| `v2rm port set [--socks P] [--http P] [--listen ADDR\|docker] [--auth USER:PASS \| --no-auth]` | Change the local proxy ports, listen address and login |

Every command has `--help`.

## Share-link options

Share links can carry options beyond the basics. v2rm keeps them on the profile, writes them into the Xray config, and round-trips them in `profile show --link`:

| Link parameter | What v2rm does |
|---|---|
| `fp` | TLS fingerprint, passed through as written (`chrome`, `firefox`, `unsafe`, …) |
| `cs` | TLS cipher suites, colon-separated → `tlsSettings.cipherSuites` |
| `ech`, `echConfigList`, `echcl` | ECH config (all three spellings) → `tlsSettings.echConfigList` |
| `fm` (URL-encoded JSON) | `streamSettings.finalmask` (TLS-hello fragmentation, noise, …) |
| `type=xhttp`, `mode`, `extra` (JSON) | XHTTP transport; `mode` and `extra` go into `xhttpSettings` |
| `encryption=mlkem768x25519plus…` | VLESS post-quantum encryption → the user's `encryption` (instead of forcing `none`) |
| `headers` (JSON or `k:v` list) | Request headers for ws / httpupgrade / xhttp. A `Host` header becomes the transport's own `host` |
| `packetEncoding`, `packet-encoding` | sing-box: mapped (`xudp`, `packetaddr`). Xray-core always uses XUDP for VLESS; other values are noted when you connect |
| `fragment` (legacy sockopt) | Kept on the profile, but not applied — `connect` tells you; use `fm` instead |
| `headerType` | Anything other than `none` is kept and noted at connect (TCP header obfuscation isn't generated) |

sing-box can't express finalmask, ECH, XHTTP/KCP, VLESS post-quantum encryption or fingerprints it doesn't know. Rather than silently dropping them and connecting a profile that then misbehaves, v2rm refuses with a message to use Xray-core. Likewise, current Xray-core has removed the `http` (h2) and `quic` transports and `allowInsecure`; links that rely on them get a clear error instead of a config Xray would reject.

## Raw Xray JSON configs

Some configs have no server at all. The best-known example is the "serverless" kind: a complete Xray config that only uses `direct`/`block`/`dns` outbounds, TLS-ClientHello fragmentation (`finalmask`), fake DNS, DoH and custom routing. It can't be expressed as server + port, so v2rm stores the whole JSON as a **raw profile** (type `raw`, shown with `—` as its server).

```bash
v2rm add --json config.json              # one config object, or an array of them (each becomes a profile)
v2rm add --json -  < config.json         # from stdin
v2rm sub add "<url of a JSON subscription>"
v2rm profile show <id> --json            # print the stored config (round-trips with `add --json -`)
v2rm profile edit <id>                   # opens the JSON in $EDITOR; refuses invalid JSON / a missing "outbounds" list
```

The name defaults to the config's `"remarks"`.

**How v2rm runs one.** The stored JSON is never run verbatim. v2rm builds the runtime config from a copy and changes *only the inbounds*:

- Only `socks`, `http` and `mixed` inbounds are kept. Anything else (`tun`, `dokodemo-door`, `tproxy`, …) is dropped, with a one-line warning naming what went.
- v2rm keeps a single proxy inbound (extra SOCKS/HTTP ones are dropped with the same warning). It is bound to the address you set with `v2rm port set --listen` — always written explicitly, because sample configs usually omit `listen`, which makes Xray bind `0.0.0.0` — and to v2rm's SOCKS port. (A config whose only inbound is `http` keeps it on v2rm's HTTP port and gains a SOCKS twin instead.)
- v2rm's HTTP port is served by an added `http` inbound (tag `<original-tag>-http`, same listen address, same `sniffing`), and that tag is appended to every `routing.rules[].inboundTag` list that contains the original tag, so the config's routing treats both alike. A `mixed` inbound already serves both on the SOCKS port. A config with no usable inbound gets a normal SOCKS + HTTP pair.
- If you set a proxy login (`--auth`), every inbound requires it.
- `dns`, `outbounds`, `routing`, `policy`, `fakedns`, `observatory`, balancers, unknown keys and `version` stay exactly as written.
- Listeners that don't come from `inbounds` — `metrics.listen` and `api.listen` — are also left as written, but `connect` and `test` name them in a note, because they sit outside the address you chose.
- **Routing presets don't apply.** A raw profile carries its own routing; `v2rm route show`, `route set`, `status` and `connect` say so instead of implying a preset is in effect.
- **Always Xray-core**, whatever `v2rm core use` says. If sing-box is your default, v2rm switches to Xray for this profile and says so in one line (your default is not changed).
- **Version check.** If the config declares `"version": {"min": …, "max": …}`, v2rm compares it numerically with the installed Xray (`26.6.27` and `v26.10.17` both work) and, if it doesn't fit, tells you to run `v2rm core update xray --pre`.
- **Pre-flight.** Before starting — in `connect` and in `test` — v2rm runs `xray run -test -c <file>` with `XRAY_LOCATION_ASSET` pointing at its geo data and shows Xray's own error output, plus a hint for the usual causes: an unknown `geosite:`/`geoip:` tag (run `v2rm route update-data --force`) or a core that is too old.
- `v2rm test` works on raw profiles like any other, with the same rewrite on throwaway ports.

### What a "serverless" config is — and isn't

A serverless config has **no remote server**. It connects *directly* and tries to defeat deep-packet-inspection filtering (for example by fragmenting the TLS ClientHello). That is DPI evasion over your normal connection, **not a VPN or tunnel**: websites still see your real IP address, and anything blocked *by IP address* stays blocked. It helps only where the block is done by inspecting handshakes/SNI. When you `v2rm test` one, a pass means "the direct connection works with the evasion in place" — v2rm says so in the output.

## MASQUE (HTTP/2)

MASQUE proxies traffic over HTTP CONNECT. Xray-core's client supports an **HTTP/2** mode (Extended CONNECT over TLS) and an HTTP/3 mode; v2rm defaults to HTTP/2 (`alpn` = `h2`; offering `h3` selects HTTP/3). MASQUE profiles run on Xray-core only — `connect` picks it automatically, and sing-box refuses them with a clear message.

```bash
v2rm add masque --server masque.example.com --port 443 --sni front.example.com \
  --user alice --pass 's3cret' --path /masque --header 'X-Token: abc' --fp chrome --name MyMasque
```

| Option | Meaning |
|---|---|
| `--server`, `--port` (443) | The MASQUE proxy |
| `--sni` | TLS server name to present |
| `--alpn` (`h2`) | `h2` = HTTP/2 mode; `h3` = HTTP/3; comma-separate to offer several |
| `--user`, `--pass` | Basic credentials (give both) |
| `--path`, `--host` | Request path (starts with `/`; `{target}`/`{ipproto}` allowed) and authority |
| `--header 'K: V'` | Extra request header, repeatable (`Host`/`Capsule-Protocol` aren't allowed; `Authorization` isn't with `--user`/`--pass`) |
| `--fp` | TLS fingerprint to imitate |
| `--name` | Display name (default `host:port`) |

v2rm checks the same rules Xray-core's own MASQUE config does when you add the profile, so mistakes show up immediately with a readable message, not as an engine start-up failure. If your Xray is too old to know MASQUE, the pre-flight says so and tells you to run `v2rm core update xray --pre` (`v2rm doctor` reports it too).

**The `masque://` link is v2rm's own convention, not an ecosystem standard** — no share-link format for MASQUE exists elsewhere. v2rm emits and parses:

```
masque://[user:pass@]host:port?sni=&alpn=h2&fp=&path=&host=&headers=<url-encoded JSON>&fm=<url-encoded JSON>#name
```

(plus optional `dns=` — comma-separated resolver IPs for Xray's `remoteDNS` — and `warp=<url-encoded JSON>`). `profile show <id> --link` prints it, so you can share or back up a profile. A full Xray config whose outbound is `masque` also works through the raw path above.

## Aether (Cloudflare WARP)

[Aether](https://github.com/CluvexStudio/Aether) is a separate program that opens a Cloudflare WARP tunnel from inside a filtered network. It **scans for a gateway that works**, proves the tunnel really carries data, and only then serves it as a local SOCKS5 proxy. v2rm installs it, keeps one WARP identity per profile, and runs it like any other engine: your listen address, ports, login and route preset still apply, and `connect`, `status`, `test`, `env`, `exec` and `doctor` work as usual.

```bash
v2rm core install aether
v2rm add aether --name "WARP h3"                            # MASQUE over HTTP/3 (QUIC) -- the default
v2rm add aether --name "WARP h2" --h2 --fragment            # MASQUE over HTTP/2 (TCP) + TLS ClientHello fragmentation
v2rm add aether --name "gool" --mode gool-classic           # WireGuard in WireGuard, both hops found by scanning
v2rm connect "WARP h2"      # scans for a gateway first: a minute or two on a filtered network, with progress shown
```

The first connection registers a free, anonymous WARP device with Cloudflare (calls to `api.cloudflareclient.com`; its keys are kept under `~/.local/share/v2rm/aether/<profile id>/`, mode `0600`, and deleted with the profile). `v2rm aether register <profile>` does just that, without connecting. Aether is AGPL-3.0 and v2rm is MIT: v2rm only downloads Aether's official release (checksum-verified) and runs it as a separate program — none of its code is part of v2rm.

### Modes

| `--mode` | What it is | Carrier |
|---|---|---|
| `masque` (default) | WARP over MASQUE | HTTP/3 (QUIC, UDP) or HTTP/2 (TCP) — `--h3` / `--h2` |
| `wg` | Classic WireGuard WARP | UDP |
| `gool` | A WireGuard WARP tunnel carried **inside** a MASQUE one: the WireGuard hop is dialled from inside WARP, so Cloudflare gives it a foreign exit address | HTTP/3 or HTTP/2 |
| `gool-classic` | The older gool: WireGuard tunnelled in WireGuard (two hops) | UDP |
| `mim` | MASQUE in MASQUE (two hops, a different exit address) | HTTP/3 or HTTP/2, the same for both hops |

**HTTP/3 or HTTP/2.** `--h3` (the default) is QUIC over UDP, the fastest handshake on a healthy network. `--h2` is HTTP/2 over TCP and looks like ordinary HTTPS: use it when UDP/QUIC is blocked or throttled. **`--fragment`** splits the TLS ClientHello (size `--fragment-size 8-16` bytes, delay `--fragment-delay 2-10` ms) for firewalls that reset a handshake whose server name ends in `cloudflareclient.com`; it applies to the HTTP/2 carrier and to the registration calls (on HTTP/3 only the latter, and v2rm says so).

**Gateways: found for you, or named by hand.** By default Aether scans (`--scan turbo|balanced|thorough|verified|ironclad`, `--ip v4|v6|both`) for a Cloudflare edge that works. To skip the scan, name them — the port is required, because which port gets through is exactly what differs between networks:

```bash
v2rm add aether --mode gool-classic --outer 162.159.192.1:2408 --inner 188.114.96.1:2408   # both hops by hand
v2rm add aether --mode gool-classic --outer 162.159.192.1:2408                             # outer by hand, the scan finds the inner one
v2rm add aether --mode gool --outer 162.159.198.1:443 --inner 188.114.96.1:2408            # MASQUE gateway + the WireGuard endpoint dialled inside it
```

The two hops must be different addresses (v2rm checks, with a readable message).

### Obfuscation, TLS, timers

| Option | Meaning |
|---|---|
| `--noize off\|light\|firewall\|balanced\|gfw\|aggressive` | Traffic obfuscation profile. Aether's default is `firewall` for MASQUE and `balanced` for WireGuard/gool; reach for `gfw` when the default does not get through |
| `--sni NAME`, `--ech auto\|BASE64`, `--ech-dns URL`, `--ech-domain NAME` | The server name the MASQUE handshakes present; Encrypted ClientHello |
| `--tls-ciphers`, `--tls-groups`, `--disable-grease`, `--no-quic-v2` | Fine-tune the TLS/QUIC fingerprint |
| `--quick-reconnect` / `--no-quick-reconnect` | Try the gateways that worked last time before scanning again (on by default; see below) |
| `--reconnect-secs`, `--startup-secs`, `--validate-secs`, `--no-data-check`, `--keepalive`, `--dns IP` | Reconnect delay after a drop, tunnel start-up and data-check time, WireGuard keepalive, resolvers inside the tunnel |
| `--wait SECONDS` | How long `connect` waits for the proxy to come up (default 120; also `V2RM_AETHER_START_TIMEOUT`). Aether scans for a gateway first, which can take longer on a heavily filtered network; a quiet scan is reported as "still working" every 20 s |
| `--exit-loc '!IR,RU'` / `--exit-loc DE,SE` | Refuse a tunnel whose exit country is wrong (checked before the proxy opens, then every minute) |
| `--mark`, `--api-address`, `--perf`, `--stats`, `--log-level` | Aether's own advanced options |
| `--env AETHER_NAME=value` | Any other Aether setting (Zero Trust, Tor, Psiphon, …), repeatable |

**Reconnecting.** Aether reconnects a dropped tunnel by itself (and rescans if the gateway is gone). With quick reconnect on, it first tries the last eight gateways that worked — saved per profile — so a restart skips the scan. `v2rm aether gateways <profile>` shows them (`--forget` clears them); `status` shows the current one. Aether keeps that memory for the `masque`, `wg` and `gool` modes; `gool-classic` and `mim` scan again after a restart — name their hops with `--outer`/`--inner` to skip it.

### Routing rules

`--block` and `--direct` take rules, repeatable; **block** is checked first, then **direct**, otherwise the tunnel is used:

| Rule | Matches |
|---|---|
| `example.com` / `domain:example.com` | the name and every subdomain |
| `full:www.example.com` | that exact name only |
| `keyword:doubleclick` | any name containing it |
| `regexp:^ad[0-9]+` | a regular expression (Rust syntax: no lookaround or back-references) |
| `10.0.0.0/8`, `1.2.3.4`, `ip:2001:db8::/32` | a network or address (IPv6 needs the `ip:` prefix) |
| `port:25`, `port:3000-3010` | a port or range |
| `private` | LAN, loopback and CGNAT space |

The name comes from the destination the client gave, **or — when the client only sent an address, as a tun front end does — from the TLS server name / HTTP Host in the first bytes of the connection** (on by default; `--no-sniff` turns it off, `--sniff-ms` sets how long to wait for those bytes). v2rm refuses a rule Aether would silently drop (an unknown type, a comma in a regexp, a bare IPv6 address, `geoip:`/`geosite:` which Aether has no data for) — for a `block` rule a silently dropped line would mean the protection is quietly off.

### An upstream proxy

`--upstream socks5://127.0.0.1:1080` (or `http://user:pass@host:8080`) makes Aether dial out through a proxy already running on this machine — another VPN client, a Tor client, an Xray you run yourself. A SOCKS5 proxy carries UDP too; an HTTP proxy carries TCP only, so v2rm then uses the HTTP/2 carrier by itself (and refuses `--h3`, `wg` and `gool-classic`, which need UDP). The password is handed to Aether through its environment, never on a command line.

### Everything else Aether can do

Aether has more than v2rm has flags for. Anything else is passed straight through with `--env AETHER_NAME=value` (repeatable, stored in the profile; `aether --help` lists every `AETHER_*` variable): Tor or Psiphon around the tunnel (`--env AETHER_TOR=chain`, `AETHER_TOR=reverse`, `AETHER_TOR=only`; `--env AETHER_PSIPHON=chain --env AETHER_PSIPHON_REGION=DE`), Zero Trust enrolment (`AETHER_TEAM`, `AETHER_ACCESS_CLIENT_ID`, `AETHER_ACCESS_CLIENT_SECRET`), and so on. v2rm refuses only the variables it owns (where Aether listens, keeps its state and dials out) and never prints the values of the ones that look like secrets. Tor and Psiphon open a second proxy of their own (`127.0.0.1:1820` / `:1821` unless `AETHER_TOR_BIND` / `AETHER_PSIPHON_BIND` say otherwise) that v2rm does not manage; the proxy v2rm serves, checks and stops is the main one.

### Sharing a setup: the `aether://` link

`v2rm profile show <id> --link` prints an `aether://MODE?param=value&…#name` link and `v2rm add "aether://…"` (or a line in a list of links) adds it again, so a setup that works on your network — `aether://masque?transport=h2&fragment=1&noize=gfw#h2-fragment` — can be passed around like a `vless://` link. Only what differs from the defaults is written, and nothing secret: the extra `AETHER_*` settings and an upstream proxy that has a login are left out (v2rm says so). The link format is v2rm's own convention, like `masque://`.

### How v2rm runs it

- With the `global` route preset and no login, Aether binds your listen address and ports itself (`--http-proxy` gives the HTTP port): one program, no Xray needed.
- With `v2rm port set --auth` or a route preset (`bypass-ir`, …), Aether moves to a loopback port and a small **Xray front** serves your address, login and preset in front of it (Aether's own SOCKS5 port has neither login nor geo rules). `connect` tells you when that happens; the front needs `v2rm core install xray`.
- Everything Aether is told goes through its **environment** (`AETHER_*`), never the command line; every `AETHER_*` variable and `RUST_LOG` in *your* shell is removed from what it inherits, and its stdin is closed so it can never stop to ask a question. `v2rm aether env <profile>` prints exactly what it is given (secrets hidden).
- `v2rm test` starts a throwaway tunnel (or tests the live proxy when that profile is the one connected — one WARP identity can carry one tunnel); `v2rm doctor` checks that `aether` runs (a glibc build on an old distribution fails right there; the default static musl build avoids it) — and `v2rm core install aether --variant gnu` is there if you want the glibc one.
- `export`/`import` carry the profile but not its WARP identity (private keys): a restored profile registers a new device on first connect, or take one over with `--identity-file path/to/aether.toml` when adding.

## Chains

A chain strings connections together; **the traffic of each hop leaves through the one before it.** Hops are listed the way the traffic travels: the first is closest to you, the last is what the internet sees. A hop is a saved profile — of any kind: a link, a subscription node, MASQUE, Hysteria2, Aether — or, as the first hop, the address of a proxy that is already running here.

```bash
v2rm chain add warp-then-server "WARP h2" "My Server"            # you -> WARP -> your server -> the internet
v2rm chain add server-then-warp "My Server" "WARP h2"            # you -> your server -> WARP -> the internet (a Cloudflare exit address)
v2rm chain add via-local socks5://127.0.0.1:1080 "WARP h2"       # a proxy already running here, then WARP
v2rm chain show warp-then-server       # hops, the program that runs each, who listens where
v2rm connect warp-then-server          # a chain is a profile: connect / test / profile use / rename / remove all work
```

- **First hop `WARP`, then a server:** Cloudflare WARP carries your connection *to the server*, so a network that blocks the server's address still reaches it. **First a server, then `WARP`:** the server carries Aether's own connection to Cloudflare, and the internet sees a WARP exit address.
- Under the hood each hop is its own program — Xray, sing-box or Aether — started in order, each dialling through the one before it (Xray `dialerProxy`, sing-box `detour`, Aether `--upstream`). Only the last one listens where you asked, with your login and route preset; the others use loopback ports v2rm picks. `v2rm status` lists every program and flags one that has stopped, and `disconnect` stops them all.
- The rules v2rm enforces, with the reason when you break one: at least two hops; a proxy address only first; a raw Xray config only first (it has outbounds of its own that can't be safely re-routed); the same Aether profile at most once (two tunnels can't share one WARP identity); an Aether profile that has an upstream of its own can't follow another hop; at most five profiles; no chain inside itself (chains may contain chains — they are unfolded).
- An Aether hop after another hop uses the HTTP/2 (TCP) carrier unless you chose HTTP/3 (UDP through the previous hop works only if its server allows UDP). Xray-only options carry over: a Hysteria2/TUIC hop runs on sing-box, a MASQUE or raw hop on Xray.
- A chain remembers each member by id and name; if a subscription refresh re-creates a node, the chain finds it again by name, and `chain list` / `doctor` say when one is truly gone. A profile that is a hop of a chain isn't removed without `--force`.

## Subscriptions

```bash
v2rm sub add "https://raw.githubusercontent.com/patterniha/Serverless-for-Iran/refs/heads/main/Subscription/Serverless-for-Iran.json#Patterniha-S"
v2rm sub add "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt#Patterniha-F"
v2rm sub list
v2rm sub update --all
```

- The text after `#` is the subscription's **name** (`Patterniha-S`, `Patterniha-F`). It is cut off before fetching — it is never sent to the server. `--name` overrides it; without either, v2rm uses a `#profile-title:` header comment, then the host name.
- **Formats** are detected from the body, in this order: Xray JSON (an object with an `outbounds` list, or an array of them → one raw profile each), Clash/Mihomo YAML, base64 link list, plain link list. Lines starting with `#` are comments and don't confuse the base64 check; `#profile-title` and `#profile-update-interval` (hours) are read, and the interval is shown by `sub show`.
- `sub update --all` always refreshes. Pass `--respect-interval` (handy for a cron job) to skip subscriptions refreshed more recently than the provider's own interval; adding `--force` overrides that again (and also lets a refresh remove the currently connected profile).
- **Same node, several variants.** Some lists ship every node several times, differing only in fingerprint / cipher suites / fragmentation / ECH. v2rm treats these as separate profiles (their identity includes SNI, host, path, network and a hash of those parameters, but never the name), so none is lost or overwritten, and refreshing an unchanged body adds and removes nothing. A raw profile is matched by its `remarks`, so a changed config with the same `remarks` is updated in place.
- If a refresh fetches nothing usable (an outage page, a truncated response), the existing profiles are kept rather than deleted.

## Routing presets

- **`global`** (default): everything sent to the proxy goes out through it. No bypass rules.
- **`bypass-ir`**: Iranian sites/IPs and private/LAN addresses go direct; everything else is tunneled.
- **`bypass-cn`**: the classic v2rayN default — mainland China and private/LAN addresses go direct.
- **`custom`**: `v2rm route edit` opens a commented YAML file (`~/.config/v2rm/routes/custom.yaml`) where you list `direct`/`block` rules by domain suffix, domain keyword, geosite category, IP range, or GeoIP code.

Presets apply to link-based profiles. **Raw profiles bring their own routing and ignore presets** (see above).

Process-based routing (matching by which app made the connection) isn't exposed as first-class commands — it overlaps with the whole point of the local SOCKS/HTTP design (you already choose which apps use the proxy), and it's fragile/platform-specific on Linux. Power users can still add `process_name`/`process_path` rules directly by hand-editing `custom.yaml` — sing-box supports them natively.

There's also no TUN/system-wide mode, by design — see the FAQ below.

## Engines: Xray-core vs sing-box (and Aether)

| Protocol / feature | Xray-core | sing-box |
|---|---|---|
| VMess | ✅ | ✅ |
| VLESS (incl. REALITY) | ✅ | ✅ |
| Trojan | ✅ | ✅ |
| Shadowsocks | ✅ | ✅ |
| Hysteria2 | ❌ | ✅ |
| TUIC | ❌ | ✅ |
| MASQUE | ✅ | ❌ |
| Raw Xray JSON configs | ✅ | ❌ |
| finalmask, ECH, XHTTP, VLESS post-quantum `encryption` | ✅ | ❌ (refused with a clear message) |

`v2rm connect` uses your default engine (Xray-core unless you ran `v2rm core use singbox`), except that profiles only one engine can run get that engine automatically, with a one-line note: raw and MASQUE profiles → Xray-core, Hysteria2/TUIC → sing-box. Connecting never changes your saved default.

**Aether** is the third program: it runs only Aether (WARP) profiles, so it is never the default engine, and chains use whichever engine each hop needs. See [Aether](#aether-cloudflare-warp) and [Chains](#chains).

## Configuration & data

All under standard XDG locations (overridable with `V2RM_CONFIG_HOME`/`V2RM_DATA_HOME`/`V2RM_STATE_HOME`/`V2RM_CACHE_HOME`):

- `~/.config/v2rm/` — profiles (raw configs included), subscriptions, app state, `routes/custom.yaml`, and `auth.json` (the proxy login, mode `0600`; it is deliberately not part of `v2rm export`)
- `~/.local/share/v2rm/bin/` — installed engine binaries (Aether's `pt/` helper folder sits beside its binary)
- `~/.local/share/v2rm/aether/<profile id>/` — an Aether profile's WARP identities (private keys, mode `0600`) and its remembered gateways; deleted with the profile, not part of `v2rm export`
- `~/.local/state/v2rm/run/` — the generated runtime config (mode `0600`, it contains your server credentials), pidfile, engine log; for a chain or an Aether profile with a front, one config and log per program (`stage-N.json`, `logs/stage-N-<engine>.log`)
- `~/.cache/v2rm/assets/` — cached GeoIP/GeoSite data

## Using v2rm from Docker

A container's `127.0.0.1` is its own loopback, so with the default setup (`127.0.0.1`) containers **can't** reach v2rm's proxy. Where the proxy listens is your decision, set with `v2rm port set --listen` and never hard-coded:

| `--listen` | Reachable from | Use it when |
|---|---|---|
| `127.0.0.1` (default) | this host only | no containers need the proxy |
| `docker` | containers on Docker's default bridge (v2rm resolves the address, usually `172.17.0.1`, and prints it) | a quick setup for the default bridge |
| a specific address, e.g. `172.18.0.1` | whatever can reach that address | one particular network |
| `0.0.0.0` | every interface and every Docker network, present and future | compose projects (each creates its own network) — pair it with a firewall and/or `--auth` |

v2rm checks that a specific address really exists on this host (`0.0.0.0` and `::` always pass), and checks it again at `connect` — a Docker bridge address only exists while Docker is running.

```bash
v2rm port set --listen docker                          # prints: Docker bridge address: 172.17.0.1 ...
# or, covering every network:
v2rm port set --listen 0.0.0.0 --auth demo:demo-pass
v2rm connect
```

> `--listen docker` looks up the **default** bridge (`docker network inspect bridge`, falling back to the `docker0` interface). Containers on other networks have their own gateways (`172.18.0.1`, `172.19.0.1`, …) and the firewall has to allow their subnets as well; if one of them can't connect, check `docker network inspect <network>` — or use `0.0.0.0`.

### Pointing a container at it

```bash
# env block for a container (written to stdout, warnings to stderr, so redirecting is safe):
v2rm env --docker > proxy.env           # uses the bridge address
v2rm env --host host.docker.internal    # or a name; the block ends up with HTTP_PROXY=http://host.docker.internal:10809, ...

docker run --rm --env-file proxy.env curlimages/curl -I https://example.com

# using the name (Docker 20.10+ on Linux): host-gateway is the default bridge address
docker run --rm --add-host=host.docker.internal:host-gateway \
  curlimages/curl -x http://demo:demo-pass@host.docker.internal:10809 -I https://example.com
```

docker compose:

```yaml
services:
  app:
    image: your/app
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      HTTP_PROXY: http://demo:demo-pass@host.docker.internal:10809     # drop "demo:demo-pass@" if you set no login
      HTTPS_PROXY: http://demo:demo-pass@host.docker.internal:10809
      ALL_PROXY: socks5h://demo:demo-pass@host.docker.internal:10808
      NO_PROXY: localhost,127.0.0.1,::1,host.docker.internal           # don't proxy traffic to the host itself
```

`v2rm env --docker` and `env --host ...` print exactly this kind of block, with the login embedded when one is set (so keep that file private). `v2rm env` / `v2rm exec` on the host use the address the proxy is really bound to and embed the login too, and `v2rm test` sends it.

### Login and firewall

Anything that can reach a non-loopback listen address can use your connection, unless you protect it. v2rm **warns but never blocks** your choice: when the proxy listens beyond localhost, `connect`, `status`, `port set` and `doctor` print a one-line warning, and if no login is set they also say the proxy is open and print the firewall commands for it:

```bash
# ufw: allow Docker's private ranges, deny everyone else
sudo ufw allow from 172.16.0.0/12 to any port 10808,10809 proto tcp
sudo ufw deny 10808,10809/tcp        # only needed if your default policy allows incoming traffic

# or iptables (these don't survive a reboot without iptables-persistent / netfilter-persistent)
sudo iptables -A INPUT -s 172.16.0.0/12 -p tcp -m multiport --dports 10808,10809 -j ACCEPT
sudo iptables -A INPUT -p tcp -m multiport --dports 10808,10809 -j DROP
```

- `--auth USER:PASS` makes both the SOCKS and HTTP ports require that login (every inbound, for every kind of profile and for both engines). It is stored in `auth.json` with mode `0600` and never printed except inside the proxy URLs you ask for (`env`, `env --docker`). SOCKS5 and HTTP proxy logins are sent unencrypted, so this is fine on localhost or a Docker bridge, not across an untrusted network. `--no-auth` removes it.
- `v2rm doctor` also looks at ufw/iptables when it can read their rules and says whether the proxy's ports are open, restricted or blocked. Reading firewall rules normally needs root, and nftables/firewalld/cloud security groups aren't covered — when it can't tell, it says "couldn't determine" instead of guessing.

## FAQ

**Why no system-wide proxy or TUN mode?** By design. v2rm only ever binds a local SOCKS/HTTP proxy; nothing on your system is redirected unless you explicitly point it there (`v2rm env`, `v2rm exec`, or your app's own proxy settings). If you want whole-system tunneling, this isn't the tool for that.

**Is a serverless config a VPN?** No. See [What a "serverless" config is — and isn't](#what-a-serverless-config-is--and-isnt): it evades DPI on a direct connection; your IP stays visible and IP-blocked sites stay blocked.

**What does registering a WARP device mean?** The first time an Aether profile connects, Aether asks Cloudflare for a free, anonymous WARP device (the same thing the official WARP app does when you install it) and keeps its keys under `~/.local/share/v2rm/aether/<profile id>/`. A profile registers when it is first connected or tested (so `v2rm test --all` registers every Aether profile that has not connected yet), or when you run `v2rm aether register`; `connect` and `test` say so before they start. Delete the profile and the keys go with it.

**Does it need root?** No. Only Aether's `--mark` option (a firewall mark on its own sockets, for a tun front end on the same router) needs `CAP_NET_ADMIN`; binding a port below 1024 needs privileges too, as always.

**Where do I get a config?** From whoever runs the server you're connecting to — a share link or a subscription URL — or, for raw configs, from whoever publishes them.

## Development

```bash
pip install -e ".[dev]"
pytest
```

Everything except actually launching a real engine binary and hitting the real network (marked `integration`, skipped by default) runs offline and deterministically, using real subscription samples saved under `tests/fixtures/`.

The integration tests run the real `xray run -test` on configs v2rm generates (nothing is started or connected): a serverless profile on several listen addresses, MASQUE profiles, and every real sample link. They also run a real chain on loopback with Xray as the server and as the previous hop, and check that the next hop's connection really leaves through it and that the Aether front enforces its login. Aether itself is exercised through small stand-in programs (`tests/fake_engines.py`), so the suite needs neither the real binary nor a WARP registration.

```bash
V2RM_INTEGRATION=1 V2RM_XRAY=/path/to/xray pytest tests/integration
# optional: V2RM_GEO_ASSETS=~/.cache/v2rm/assets  (the directory `v2rm route update-data` fills)
```

## License

MIT — see [LICENSE](LICENSE). [Aether](https://github.com/CluvexStudio/Aether) is a separate program under the AGPL-3.0; v2rm downloads its official release and runs it as a separate process, and none of its code is bundled or linked.
