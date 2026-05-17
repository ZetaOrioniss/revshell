# REVSHELL >

**Author:** ZetaOrioniss\
**Version:** 1.1

**REVSHELL** is an interactive Python utility designed to streamline the generation of reverse shells and listener management during penetration testing. No more manual copying and pasting from websites: everything is centralized in an ergonomic console.

> ⚠️ **Disclaimer**: This tool is strictly intended for educational and professional use within the framework of authorized penetration testing. The author declines all responsibility for any illegal use.

![screenshot](https://github.com/ZetaOrioniss/revshell/blob/main/assets/example.png)

---

## 1. Why use REVSHELL?

The tool addresses three main needs for pentesters and cybersecurity students:

* **Speed & Efficiency**: Instantly generate dozens of payloads (Bash, Python, PowerShell, PHP, etc.) by configuring your IP and Port once.
* **Console Comfort**: Benefit from a syntax similar to Metasploit with **full auto-completion (Tab key)** so you never have to hunt for commands.
* **All-in-one Workflow**: No need to open another terminal for your listener. You can generate your payload and launch a `netcat`/`rlwrap` listener directly from the tool.
* **Interface-aware LHOST**: Browse all your network interfaces and their IPv4 addresses directly from the console — no more `ip a` in a separate terminal.

---

## 2. Installation & Dependencies

### Prerequisites

The tool is written in Python 3 and requires no external Python libraries (standard library only).

However, to fully benefit from the listener features, it is recommended to have:

* `netcat` (or `ncat` / `netcat-openbsd`)
* `rlwrap` (optional, for a remote shell with history and arrow key support)

### Installation

1. **Clone the repository**

```bash
git clone https://github.com/ZetaOrioniss/revshell.git
cd revshell
```

2. **Make the script executable**

```bash
chmod +x revshell.py
```

3. **Install system dependencies (Debian / Ubuntu / Kali)**

```bash
sudo apt update && sudo apt install rlwrap netcat-openbsd -y
```

---

## 3. Usage Guide 🖥️

Launch the interactive interface with the following command:

```bash
./revshell.py
```

---

## 4. Command Reference

### ⚙️ Configuration

| Command | Description |
|---|---|
| `load config` | Load the IP and Port from `conf.json` (auto-saved on `set`) |
| `set ip <address\|interface>` | Set LHOST — accepts a raw IP **or** an interface name (e.g. `tun0`) |
| `set port <port>` | Set LPORT. *Alias: lport* |
| `unset ip\|port` | Clear a configured value |
| `show options` | Display the current LHOST / LPORT |

### 🌐 Network Interfaces

| Command | Description |
|---|---|
| `ifconfig` / `interfaces` | List all UP interfaces with their IPv4 addresses |
| `ifconfig pick` | Interactive numbered picker — select an interface to set as LHOST |
| `ifconfig <name>` | Highlight a specific interface in the table |

### 🚀 Payload Management

| Command | Description |
|---|---|
| `show` | List all available payloads with their key and OS |
| `use <name>` | Display a specific payload |
| `run` / `generate` | Generate all payloads with the current LHOST / LPORT |
| `run <name>` | Generate a specific payload |
| `run --unix` | Filter for **Unix / Linux** payloads only |
| `run --windows` | Filter for **Windows** payloads only |

### 🎧 Listener

| Command | Description |
|---|---|
| `listener` | Start `nc -lvnp <LPORT>` |
| `rlwrap` | Start the listener via `rlwrap` (recommended for a stable TTY) |

### 🔧 Miscellaneous

| Command | Description |
|---|---|
| `clear` | Clear the screen |
| `help` | Display the full command reference |
| `exit` / `quit` | Exit the console |

---

## 5. Workflow Examples

### Standard setup — IP and port

```
revshell (-:-) > set ip 10.10.14.5
  LHOST => 10.10.14.5
revshell (10.10.14.5:-) > set port 4444
  LPORT => 4444
revshell (10.10.14.5:4444) > run --unix
```

### HTB / VPN — Set LHOST from interface name

No need to copy-paste from `ip a`. Pass the interface name directly:

```
revshell (-:-) > set ip tun0
  LHOST => 10.10.14.5  (resolved from interface tun0)
```

### Browse all interfaces — pick interactively

```
revshell (-:-) > ifconfig pick

  #    INTERFACE          IPv4
  ─────────────────────────────────────────────────────
  1.   eth0               192.168.1.42
  2.   tun0               10.10.14.5
  3.   docker0            172.17.0.1

Enter number or interface name: 2
  LHOST => 10.10.14.5  (tun0)
```

### Generate a specific payload

```
revshell (10.10.14.5:4444) > use python
revshell (10.10.14.5:4444) > run bash
```

### Launch listener, wait for the shell

```
revshell (10.10.14.5:4444) > rlwrap
  Starting listener:  rlwrap nc -lvnp 4444
  Waiting for connection on port 4444 ... (Ctrl+C to stop)
```

---

## 6. Interface Resolution

`set ip` accepts either a raw IPv4 address or a **network interface name**. When an interface name is given, REVSHELL resolves its current IPv4 automatically and persists the IP (not the interface name) to `conf.json`.

Interface detection works without any external library via three methods in cascade:

1. `ioctl SIOCGIFADDR` (Linux kernel, fastest)
2. `ip -4 addr show` (iproute2)
3. `ifconfig` (legacy fallback)

Tab completion on `set ip <Tab>` lists available interface names alongside manual input.

---

## 7. Tab Completion

Every command, sub-command, flag, and interface name supports `Tab` completion:

```
set ip <Tab>          → eth0  tun0  docker0  …
ifconfig <Tab>        → pick  eth0  tun0  …
run <Tab>             → bash  python  php  nc  powershell  …
run --<Tab>           → --unix  --windows
```
