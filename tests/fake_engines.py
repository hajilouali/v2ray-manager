"""Stand-ins for the engine programs, for tests that really start processes.

    python fake_engines.py aether              -> behaves like `aether`, configured by AETHER_* variables
    python fake_engines.py engine run -c FILE  -> behaves like `xray run -c FILE` / `sing-box run -c FILE`

Both listen like the real thing, answer a SOCKS5 greeting, write a log in Aether's style, and
append a line to the file named by FAKE_ENGINE_EVENTS so a test can see the order they started in.
What the aether stand-in does is set by AETHER_FAKE_BEHAVIOUR (an AETHER_* variable, so a profile can set it through its extra env):

    ok           (default) scan for a moment, then open the SOCKS5 port
    slow:N       wait N seconds before opening the port
    prebind      bind and drop the port first, as the real Aether does, and open it for real later
    exit         print an error and exit with code 1
    never        run forever without ever opening the port

Set AETHER_FAKE_PROXY=1 and the aether stand-in is a working SOCKS5 proxy (CONNECT only, no login)
that relays to whatever it is asked for and records "relay HOST:PORT" in the events file -- so a
test can send real traffic through a stack and see which hop carried it.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import sys
import threading
import time


def event(text: str) -> None:
    path = os.environ.get("FAKE_ENGINE_EVENTS")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")


def log(message: str) -> None:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    print(f"[{stamp}.000Z INFO  aether] {message}", flush=True)


def split_address(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    return host.strip("[]"), int(port)


def pump(source: socket.socket, sink: socket.socket) -> None:
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            sink.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (source, sink):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def relay(conn: socket.socket) -> None:
    """The rest of a SOCKS5 CONNECT after the greeting: read the request, connect, relay."""
    head = conn.recv(4)
    if len(head) < 4 or head[1] != 1:
        return
    if head[3] == 1:
        host = socket.inet_ntoa(conn.recv(4))
    elif head[3] == 3:
        host = conn.recv(conn.recv(1)[0]).decode()
    else:
        host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
    port = int.from_bytes(conn.recv(2), "big")
    event(f"relay {host}:{port}")
    try:
        upstream = socket.create_connection((host, port), timeout=5)
    except OSError:
        conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        return
    conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    conn.settimeout(None)
    threading.Thread(target=pump, args=(upstream, conn), daemon=True).start()
    pump(conn, upstream)


def serve(host: str, port: int, proxy: bool = False) -> None:
    server = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(16)

    def handle(conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            greeting = conn.recv(3)
            if greeting[:1] == b"\x05":
                conn.sendall(b"\x05\x00")
                if proxy:
                    relay(conn)
        except OSError:
            pass
        finally:
            conn.close()

    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def stop_on_term() -> None:
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))


def aether() -> int:
    if "--version" in sys.argv:
        print("aether 0.0.0-fake")
        return 0
    stop_on_term()
    env = os.environ
    record = env.get("AETHER_FAKE_RECORD")
    if record:
        with open(record, "w", encoding="utf-8") as fh:
            json.dump({k: v for k, v in env.items() if k.startswith("AETHER_") or k == "RUST_LOG"}, fh)
            fh.write("\n")
            json.dump({"cwd": os.getcwd(), "stdin_is_tty": sys.stdin.isatty() if sys.stdin else False}, fh)

    host, port = split_address(env["AETHER_SOCKS"])
    event(f"aether {port}")
    log("Aether v0.0.0-fake")
    behaviour = env.get("AETHER_FAKE_BEHAVIOUR", "ok")

    if behaviour == "exit":
        print("Error: the socks5 listener cannot use that address: fake failure", file=sys.stderr, flush=True)
        return 1

    log("[*] hunting for a working MASQUE gateway (deep connect-ip verification)")
    if behaviour == "never":
        log("[-] no usable MASQUE gateway found: fake; rescanning shortly")
        while True:
            time.sleep(1)
    if behaviour == "prebind":
        probe = socket.socket()
        probe.bind((host, port))
        probe.listen(1)
        probe.close()
        time.sleep(1.5)
    if behaviour.startswith("slow:"):
        time.sleep(float(behaviour.split(":", 1)[1]))
    else:
        time.sleep(0.2)
    log("[+] using cloudflare edge 162.159.198.1:443")
    log("[+] masque tunnel validated (end-to-end data confirmed); exposing socks5")
    log(f"[+] socks5 server listening on {host}:{port}")
    serve(host, port, proxy=env.get("AETHER_FAKE_PROXY") == "1")
    return 0


def engine() -> int:
    stop_on_term()
    config_path = sys.argv[sys.argv.index("-c") + 1]
    with open(config_path, encoding="utf-8") as fh:
        config = json.load(fh)
    listeners = []
    for inbound in config.get("inbounds", []):
        port = inbound.get("port") or inbound.get("listen_port")
        host = inbound.get("listen") or "127.0.0.1"
        if host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        listeners.append((host, int(port)))
    event(f"engine {listeners[0][1]}")
    print("fake engine started", flush=True)
    for host, port in listeners[1:]:
        threading.Thread(target=serve, args=(host, port), daemon=True).start()
    serve(*listeners[0])
    return 0


if __name__ == "__main__":
    sys.exit(aether() if sys.argv[1] == "aether" else engine())
