from __future__ import annotations

APP_NAME = "v2rm"

DEFAULT_SOCKS_PORT = 10808
DEFAULT_HTTP_PORT = 10809
DEFAULT_LISTEN_ADDRESS = "127.0.0.1"

ENV_CONFIG_HOME = "V2RM_CONFIG_HOME"
ENV_DATA_HOME = "V2RM_DATA_HOME"
ENV_STATE_HOME = "V2RM_STATE_HOME"
ENV_CACHE_HOME = "V2RM_CACHE_HOME"

GITHUB_API = "https://api.github.com"
XRAY_REPO = "XTLS/Xray-core"
SINGBOX_REPO = "SagerNet/sing-box"
# Aether is AGPL-3.0 and v2rm is MIT: v2rm only downloads the official release binary and runs
# it as a separate program, it never bundles or links Aether's code.
AETHER_REPO = "CluvexStudio/Aether"

# sing-box rule-set (.srs) sources -- see SagerNet/sing-geoip and SagerNet/sing-geosite,
# branch "rule-set". Deprecated inline geoip/geosite fields are intentionally not used.
GEOIP_RULESET_BASE = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set"
GEOSITE_RULESET_BASE = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set"

# Xray-core has no rule-set concept; it resolves geoip:x/geosite:x tags against these
# classic .dat files, loaded via the XRAY_LOCATION_ASSET env var at process launch.
XRAY_GEOIP_DAT_URL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
XRAY_GEOSITE_DAT_URL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

DEFAULT_USER_AGENT = "v2rm/0.1.0"

# The test reads only the first TEST_DOWNLOAD_BYTES of whichever URL answers, so a larger
# file is fine. (CacheFly serves 1mb/10mb/100mb.test; the 2mb.test this used to point at
# returns 404, which silently disabled the fallback.)
TEST_URLS = [
    "https://speed.cloudflare.com/__down?bytes=2000000",
    "https://cachefly.cachefly.net/10mb.test",
]
TEST_DOWNLOAD_BYTES = 2_000_000
TEST_TIMEOUT_SECONDS = 10.0
TEST_CHUNK_SIZE = 65536

CONNECT_POLL_TIMEOUT = 2.0
CONNECT_POLL_INTERVAL = 0.1
DISCONNECT_GRACE_SECONDS = 3.0
# After a port answers, how long a program gets to prove it is the one serving it (see supervisor._settle).
READY_SETTLE_SECONDS = 0.25
# Aether checks its SOCKS port and decides to start or stop in the first moments after it is launched.
AETHER_SETTLE_SECONDS = 0.75

# Aether scans for a working Cloudflare gateway and proves the tunnel carries data before it opens
# its SOCKS port, which takes seconds to minutes -- not the two seconds Xray needs.
AETHER_START_TIMEOUT = 120.0
AETHER_POLL_INTERVAL = 0.5

ENGINE_XRAY = "xray"
ENGINE_SINGBOX = "singbox"
ENGINE_AETHER = "aether"
