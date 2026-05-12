# REVSHELL >

**Author:** ZetaOrioniss\
**Version:** 1.0

**REVSHELL** is an interactive Python utility designed to streamline the generation of reverse shells and listener management during penetration testing. No more manual copying and pasting from websites: everything is centralized in an ergonomic console.

⚠️ **Disclaimer**: This tool is strictly intended for educational and professional use within the framework of authorized penetration testing. The author declines all responsibility for any illegal use.

---

## 1. Why use REVSHELL?

The tool addresses three main needs for pentesters and cybersecurity students:

* **Speed & Efficiency**: Instantly generate dozens of payloads (Bash, Python, PowerShell, PHP, etc.) by configuring your IP and Port once.
* **Console Comfort**: Benefit from a syntax similar to Metasploit with **full auto-completion (Tab key)** so you never have to hunt for commands.
* **All-in-one Workflow**: No need to open another terminal for your listener. You can generate your payload and launch a `netcat`/`rlwrap` listener directly from the tool.

## 2. Installation & Dependencies

### Prerequisites

The tool is written in Python3 and requires no external Python libraries (standard library only).

However, to fully benefit from the listener features, it is recommended to have:

* `netcat` (or `ncat`/`netcat-openbsd`)
* `rlwrap` (optional, for a remote shell with history and arrow key support).

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

3. **Install system dependencies (Debian/Ubuntu/Kali)**

```bash
sudo apt update && sudo apt install rlwrap netcat-openbsd -y

```

---

## 3. Usage Guide 🖥️

Launch the interactive interface with the following command:

```bash
./revshell.py

```

## Help

#### **Configuration**

| Command | Description |
| --- | --- |
| `set ip <address>` | Sets the local IP (**LHOST**). *Aliases: host, lhost* |
| `set port <port>` | Sets the local port (**LPORT**). *Alias: lport* |
| `unset ip|port` | Clears the configured value. |
| `show options` | Displays the current configuration. |

#### **Payload Management**

| Command | Description |
| --- | --- |
| `show` | Lists all available payloads. |
| `use <name>` | Displays a specific payload without filters. |
| `run` / `generate` | Generates all payloads with current IP/Port. |
| `run <name>` | Generates a specific payload. |
| `run --unix` | Filters for **Unix/Linux** payloads only. |
| `run --windows` | Filters for **Windows** payloads only. |

#### **Listening (Listener)**

| Command | Description |
| --- | --- |
| `listener` | Launches a standard listener: `nc -lvnp <LPORT>`. |
| `rlwrap` | Launches the listener with `rlwrap` for a better TTY. |

#### **Miscellaneous**

| Command | Description |
| --- | --- |
| `clear` | Clears the screen content. |
| `help` | Displays help and the list of commands. |
| `exit` / `quit` | Exits the **REVSHELL** console. |

---

### ⚙️ Setting Parameters

Before generating a shell, you must define your listening IP address (**LHOST**) and your port (**LPORT**). The console supports auto-completion with the `Tab` key.

* `set ip 10.10.14.5`: Sets your machine's IP address.
* `set port 4444`: Sets the local port for the incoming connection.
* `show options`: Displays current configuration for verification.

### 🚀 Generating Payloads

Once configured, you can view the commands to copy-paste onto the target:

* `run`: Displays **all** available shells (Bash, Python, PHP, etc.) with your IP/Port injected.
* `run --unix`: Filters and displays only **Linux/Unix** compatible shells.
* `run --windows`: Filters and displays only **Windows** shells (PowerShell).
* `use <key>`: Displays a specific payload (e.g., `use bash` or `use php`).

### 🎧 Listener Management

No need to leave the tool to wait for the connection. Launch the listener directly from the console:

* `listener`: Launches a standard `nc -lvnp` command.
* `rlwrap`: Launches the listener via `rlwrap`. **Highly recommended** for a more stable shell with history and arrow key support.

---

### Upcoming Features

For better user experience and to avoid searching for your IP, **REVSHELL** will soon display all IPv4 addresses of the different network interfaces in a single command.
