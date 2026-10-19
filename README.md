# v2rm

[🇮🇷 مستندات فارسی](README.fa.md)

**v2rm** is a friendly command-line manager for [Xray-core](https://github.com/XTLS/Xray-core) and [sing-box](https://github.com/SagerNet/sing-box) on Linux. It brings the everyday workflow of v2rayN (the Windows GUI client) to the terminal: add configs from share links or complete Xray JSON files, subscribe to and refresh subscription URLs, edit configs, really test whether one works, and switch your active connection — all from one small tool.

**v2rm never touches system-wide proxy settings.** Connecting starts a local SOCKS5 + HTTP proxy on `127.0.0.1` (or on the address *you* choose with `v2rm port set --listen`) and nothing else. Only the applications you explicitly point at that port use it; everything else on your machine keeps its normal, direct internet connection.

## Features

- **Add configs** from `vmess://`, `vless://` (including VLESS+REALITY), `trojan://`, `ss://` (SIP002 and legacy), `hysteria2://`/`hy2://`, `tuic://` and `masque://` share links — one at a time, from a file, or piped in from stdin. Links can carry the newer Xray options too: `fp=unsafe`, `cs` (cipher suites), `ech`, `fm` (finalmask / TLS-hello fragmentation), XHTTP `mode`/`extra`, VLESS post-quantum `encryption`, `headers`, `packetEncoding` (see [Share-link options](#share-link-options)).
- **Complete Xray JSON configs ("raw" profiles)**: add a whole Xray config — a file, an array of them, or a JSON subscription — and v2rm runs it as written, replacing only its inbounds so v2rm's local-proxy guarantees still hold. See [Raw Xray JSON configs](#raw-xray-json-configs).
- **MASQUE (HTTP/2) profiles** for Xray-core: `v2rm add masque ...`. See [MASQUE](#masque-http2).
- **Subscriptions**: add a subscription URL and refresh it later. Auto-detects Xray JSON, plain link lists (including ones with `#profile-title` / `#profile-update-interval` header comments), base64 link lists, and Clash/Mihomo YAML. A `#name` at the end of the URL becomes the subscription's name and is never sent to the server. Refreshing diffs the new list against what you have — it adds new nodes, drops ones that disappeared, and updates the rest in place, matching by server identity (not name) so a provider renaming a node doesn't create a duplicate or break your active connection.
- **Edit configs** in place, either with `--flag` options for common fields or by opening the full profile (YAML, or the JSON config for a raw profile) in `$EDITOR`.
- **Real connectivity testing**: `v2rm test` doesn't just ping a config — it spins up a throwaway instance of the engine, connects through it, and actually downloads a small file, reporting real latency and throughput. `test --all` does this for every saved profile in parallel and ranks the results.
- **Switch connections** in one command, live, with `v2rm connect <profile>` or `v2rm profile use <profile>`.
- **Local SOCKS + HTTP proxy only.** No TUN device, no system/NetworkManager proxy changes, ever. Use `v2rm env` to opt one shell session in (`eval "$(v2rm env)"`), or `v2rm exec -- <command>` to run a single command through it — nothing else is affected.
- **You choose where it listens**: loopback (the default), a specific address, the Docker bridge (`--listen docker`) or every interface (`0.0.0.0`) — with an optional login (`--auth USER:PASS`), warnings when the proxy is reachable beyond localhost, and a `doctor` that looks at your firewall. See [Using v2rm from Docker](#using-v2rm-from-docker).
- **Two swappable engines** — Xray-core and sing-box — installed, updated, and switched with `v2rm core`. sing-box additionally covers Hysteria2 and TUIC, which Xray-core doesn't support; Xray-core covers MASQUE, raw configs and the newer link options, which sing-box doesn't.
- **Routing rules**: built-in `global` (proxy everything), `bypass-cn` (v2rayN's classic mainland-China bypass), and `bypass-ir` (direct-routes Iranian sites/IPs and LAN, tunnels everything else) presets, plus a hand-editable `custom` rule file.
- **A friendly interactive menu** (just run `v2rm`) for everyday use — including "Add a JSON config" and "Add a MASQUE server" — backed by the exact same commands available on the command line for scripting.

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

Raw configs, MASQUE and several link options need a recent Xray-core. Run `v2rm core update xray`, then `v2rm doctor` to see exactly what your Xray supports.

## Quick start

```bash
# Add a config from a share link
v2rm add "vless://uuid@host:443?security=reality&sni=example.com&pbk=...&sid=...&flow=xtls-rprx-vision#My Server"

# ...or a complete Xray JSON config (one object, or an array of them)
v2rm add --json config.json
curl -s https://example.com/config.json | v2rm add --json -

# ...or a MASQUE server (HTTP/2)
v2rm add masque --server masque.example.com --sni front.example.com --user alice --pass 's3cret' --path /masque

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
| `v2rm doctor` | Environment/engine diagnostics: Xray version, MASQUE/finalmask support, geo data, who can reach the proxy, firewall |
| `v2rm profile list [--subscription S] [--protocol P]` | List profiles (Type column: `vless`, `trojan`, `masque`, `raw`, ...) |
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
| `v2rm core install <xray\|singbox> [--version V]` | Download and install an engine |
| `v2rm core update <xray\|singbox>` | Update to the latest release |
| `v2rm core use <xray\|singbox>` | Set the default engine |
| `v2rm core remove <xray\|singbox> [--version V] [--all]` | Remove installed engine version(s) |
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
- **Routing presets don't apply.** A raw profile carries its own routing; `v2rm route show`, `route set`, `status` and `connect` say so instead of implying a preset is in effect.
- **Always Xray-core**, whatever `v2rm core use` says. If sing-box is your default, v2rm switches to Xray for this profile and says so in one line (your default is not changed).
- **Version check.** If the config declares `"version": {"min": …, "max": …}`, v2rm compares it numerically with the installed Xray (`26.6.27` and `v26.10.17` both work) and, if it doesn't fit, tells you to run `v2rm core update xray`.
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

v2rm checks the same rules Xray-core's own MASQUE config does when you add the profile, so mistakes show up immediately with a readable message, not as an engine start-up failure. If your Xray is too old to know MASQUE, the pre-flight says so and tells you to run `v2rm core update xray` (`v2rm doctor` reports it too).

**The `masque://` link is v2rm's own convention, not an ecosystem standard** — no share-link format for MASQUE exists elsewhere. v2rm emits and parses:

```
masque://[user:pass@]host:port?sni=&alpn=h2&fp=&path=&host=&headers=<url-encoded JSON>&fm=<url-encoded JSON>#name
```

(plus optional `dns=` — comma-separated resolver IPs for Xray's `remoteDNS` — and `warp=<url-encoded JSON>`). `profile show <id> --link` prints it, so you can share or back up a profile. A full Xray config whose outbound is `masque` also works through the raw path above.

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

## Engines: Xray-core vs sing-box

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

## Configuration & data

All under standard XDG locations (overridable with `V2RM_CONFIG_HOME`/`V2RM_DATA_HOME`/`V2RM_STATE_HOME`/`V2RM_CACHE_HOME`):

- `~/.config/v2rm/` — profiles (raw configs included), subscriptions, app state, `routes/custom.yaml`, and `auth.json` (the proxy login, mode `0600`; it is deliberately not part of `v2rm export`)
- `~/.local/share/v2rm/bin/` — installed engine binaries
- `~/.local/state/v2rm/run/` — the generated runtime config (mode `0600`, it contains your server credentials), pidfile, engine log
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

**Where do I get a config?** From whoever runs the server you're connecting to — a share link or a subscription URL — or, for raw configs, from whoever publishes them.

## Development

```bash
pip install -e ".[dev]"
pytest
```

Everything except actually launching a real engine binary and hitting the real network (marked `integration`, skipped by default) runs offline and deterministically, using real subscription samples saved under `tests/fixtures/`.

The integration tests run the real `xray run -test` on configs v2rm generates (nothing is started or connected): a serverless profile on several listen addresses, MASQUE profiles, and every real sample link.

```bash
V2RM_INTEGRATION=1 V2RM_XRAY=/path/to/xray pytest tests/integration
# optional: V2RM_GEO_ASSETS=~/.cache/v2rm/assets  (the directory `v2rm route update-data` fills)
```

## License

MIT — see [LICENSE](LICENSE).
