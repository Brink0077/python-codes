#!/usr/bin/env python3
import socket
import time
import sys
import os
import glob
from typing import Optional, List, Dict, Tuple


# -------------------------
# Built-in Zeek filename -> Tag map
# -------------------------
DEFAULT_ZEEK_TAGS: Dict[str, str] = {
    "notice.log": "zeek_notice",
    "weird.log": "zeek_weird",
    "conn.log": "zeek_conn",
    "dns.log": "zeek_dns",
    "dhcp.log": "zeek_dhcp",
    "http.log": "zeek_http",
    "software.log": "zeek_software",
    "tunnel.log": "zeek_tunnel",
    "smtp.log": "zeek_smtp",
    "zeekker.log": "zeek_zeekker",
    "capture_loss.log": "zeek_capture_loss",
    "cluster.log": "zeek_cluster",
    "dce_rpc.log": "zeek_dce_rpc",
    "files.log": "zeek_files",
    "ftp.log": "zeek_ftp",
    "irc.log": "zeek_irc",
    "kerberos.log": "zeek_kerberos",
    "mysql.log": "zeek_mysql",
    "ntlm.log": "zeek_ntlm",
    "packet_filter.log": "zeek_packet_filter",
    "pe.log": "zeek_pe",
    "radius.log": "zeek_radius",
    "reporter.log": "zeek_reporter",
    "rdp.log": "zeek_rdp",
    "sip.log": "zeek_sip",
    "smb_files.log": "zeek_smb_files",
    "smb_mapping.log": "zeek_smb_mapping",
    "snmp.log": "zeek_snmp",
    "ssh.log": "zeek_ssh",
    "ssl.log": "zeek_ssl",
    "stats.log": "zeek_stats",
    "x509.log": "zeek_x509",
    "dpd.log": "zeek_dpd",
    "ocsp.log": "zeek_ocsp",
    "intel.log": "zeek_intel",
    "ldap.log": "zeek_ldap",
    "quic.log": "zeek_quic",
    "socks.log": "zeek_socks",
    "suricata_corelight.log": "zeek_suricata_corelight",
    "syslog.log": "zeek_syslog",
    "websocket.log": "zeek_websocket",
    "yara.log": "zeek_yara",
}


# -------------------------
# Syslog (RFC3164) helpers
# -------------------------
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

def rfc3164_timestamp(now: Optional[time.struct_time] = None) -> str:
    if now is None:
        now = time.localtime()
    mon = _MONTHS[now.tm_mon - 1]
    day = f"{now.tm_mday:2d}"  # space padded
    return f"{mon} {day} {now.tm_hour:02d}:{now.tm_min:02d}:{now.tm_sec:02d}"

def calc_pri(facility: int, severity: int) -> int:
    return facility * 8 + severity

def format_rfc3164(message: str,
                   hostname: str,
                   tag: str,
                   facility: int = 1,
                   severity: int = 6,
                   zeek_style: bool = False) -> str:
    """
    Standard RFC3164:
      <PRI>TIMESTAMP HOST TAG: MESSAGE

    Zeek-style (requested):
      <PRI>TIMESTAMP HOST TAG MESSAGE
      (no colon after TAG)
    """
    pri = calc_pri(facility, severity)
    ts = rfc3164_timestamp()
    msg = message.rstrip("\r\n")
    if zeek_style:
        return f"<{pri}>{ts} {hostname} {tag} {msg}"
    return f"<{pri}>{ts} {hostname} {tag}: {msg}"

def format_raw(message: str) -> str:
    return message.rstrip("\r\n")


# -------------------------
# Streaming file reader
# -------------------------
class StreamingLineSource:
    def __init__(self, file_path: str, stop_at_eof: bool = False,
                 encoding: str = "utf-8", errors: str = "replace"):
        self.file_path = file_path
        self.stop_at_eof = stop_at_eof
        self.encoding = encoding
        self.errors = errors
        self._fh = None

    def _open(self):
        self._fh = open(self.file_path, "r", encoding=self.encoding, errors=self.errors)

    def next_line(self) -> str:
        if self._fh is None:
            self._open()

        line = self._fh.readline()
        if line != "":
            return line

        if self.stop_at_eof:
            raise StopIteration

        self._fh.close()
        self._open()
        line = self._fh.readline()
        if line == "":
            raise ValueError(f"Error: File '{self.file_path}' is empty.")
        return line

    def close(self):
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None


# -------------------------
# Connection helpers
# -------------------------
def connect_tcp(ip: str, port: int, timeout: float = 5.0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((ip, port))
    s.settimeout(None)
    return s

def safe_close(sock: Optional[socket.socket]):
    if sock is None:
        return
    try:
        sock.close()
    except Exception:
        pass


# -------------------------
# Input expansion: file / dir / glob
# -------------------------

def expand_inputs(path_or_pattern: str) -> List[str]:
    """
    Accepts:
      - directory: includes ALL regular files in that directory
      - glob: uses glob pattern (can match .log/.txt/.json/anything)
      - single file path: uses that file
    Returns a sorted list of files.
    """
    # Directory => include all regular files (any extension)
    if os.path.isdir(path_or_pattern):
        try:
            entries = [os.path.join(path_or_pattern, name) for name in os.listdir(path_or_pattern)]
        except Exception:
            return []
        files = [p for p in entries if os.path.isfile(p)]
        files.sort()
        return files

    # Glob pattern or plain file path
    files = glob.glob(path_or_pattern, recursive=True)
    files = [f for f in files if os.path.isfile(f)]
    files.sort()

    if not files and os.path.isfile(path_or_pattern):
        return [path_or_pattern]

    return files


# -------------------------
# Service mapping helpers
# -------------------------
def parse_service_map_arg(arg: Optional[str]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if not arg:
        return mapping
    parts = [p.strip() for p in arg.split(",") if p.strip()]
    for p in parts:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k and v:
            mapping[k] = v
    return mapping


# -------------------------
# Main sender
# -------------------------
def send_log(ip: str,
             port: int,
             input_path_or_pattern: str,
             count: int,
             eps: int,
             protocol: int,
             facility: int = 1,
             severity: int = 6,
             default_tag: str = "trafficGenerator",
             hostname: Optional[str] = None,
             tcp_retries: int = 10,
             tcp_backoff_start: float = 0.25,
             tcp_backoff_max: float = 3.0,
             fmt: str = "rfc3164",
             mode: str = "paced",
             burst_delay: float = 0.0,
             tcp_append_newline: bool = True,
             stop_at_eof: bool = False,
             service: Optional[str] = None,
             service_map_arg: Optional[str] = None):

    if eps <= 0:
        print("Error: eps must be > 0.")
        return
    if count <= 0:
        print("Error: count must be > 0.")
        return

    if hostname is None:
        hostname = socket.gethostname() or "localhost"

    if fmt not in ("rfc3164", "raw"):
        print("Error: --format must be 'rfc3164' or 'raw'")
        return
    if mode not in ("paced", "burst"):
        print("Error: --mode must be 'paced' or 'burst'")
        return

    is_tcp = (protocol == 1)
    is_udp = (protocol == 0)
    if not (is_tcp or is_udp):
        print("Error: Invalid protocol. Use 1 for TCP or 0 for UDP.")
        return

    files = expand_inputs(input_path_or_pattern)
    if not files:
        print(f"Error: No files found for '{input_path_or_pattern}'")
        return

    cli_map = parse_service_map_arg(service_map_arg)

    def is_zeek_file(fp: str) -> bool:
        return os.path.basename(fp) in DEFAULT_ZEEK_TAGS

    def pick_tag_for_file(fp: str) -> str:
        base = os.path.basename(fp)
        if base in cli_map:
            return cli_map[base]
        if base in DEFAULT_ZEEK_TAGS:
            return DEFAULT_ZEEK_TAGS[base]
        if service:
            return service
        return default_tag

    sock = None

    def ensure_tcp_connected() -> bool:
        nonlocal sock
        if not is_tcp:
            return True
        if sock is not None:
            return True

        backoff = tcp_backoff_start
        last_err = None
        for _ in range(tcp_retries):
            try:
                sock = connect_tcp(ip, port)
                return True
            except Exception as e:
                last_err = e
                time.sleep(backoff)
                backoff = min(tcp_backoff_max, backoff * 2)

        print(f"\nError: Unable to connect to {ip}:{port} after {tcp_retries} retries: {last_err}")
        return False

    def build_wire(line: str, tag_for_this_line: str, zeek_style: bool) -> bytes:
        if fmt == "rfc3164":
            out = format_rfc3164(line, hostname, tag_for_this_line, facility, severity, zeek_style=zeek_style)
        else:
            out = format_raw(line)

        if is_tcp and tcp_append_newline:
            out += "\n"

        return out.encode("utf-8", errors="replace")

    def send_one(wire: bytes) -> bool:
        nonlocal sock
        try:
            if is_tcp:
                sock.sendall(wire)
            else:
                sock.sendto(wire, (ip, port))
            return True
        except Exception as e:
            if is_tcp:
                safe_close(sock)
                sock = None
                if not ensure_tcp_connected():
                    print(f"\nError: TCP send failed and reconnect failed: {e}")
                    return False
                try:
                    sock.sendall(wire)
                    return True
                except Exception as e2:
                    print(f"\nError: TCP resend after reconnect failed: {e2}")
                    return False
            return True

    def send_file_once(file_path: str) -> int:
        sent = 0
        tag_for_file = pick_tag_for_file(file_path)
        zeek_style = is_zeek_file(file_path)  # <-- ONLY zeek filenames get "no colon" format

        src = StreamingLineSource(file_path, stop_at_eof=True)
        try:
            if mode == "paced":
                interval = 1.0 / float(eps)
                next_send = time.perf_counter()
                while True:
                    now = time.perf_counter()
                    if now < next_send:
                        time.sleep(next_send - now)

                    try:
                        line = src.next_line()
                    except StopIteration:
                        break

                    wire = build_wire(line, tag_for_file, zeek_style)
                    if not send_one(wire):
                        raise RuntimeError("Fatal send error")

                    sent += 1
                    next_send += interval
            else:
                while True:
                    burst_sent = 0
                    while burst_sent < eps:
                        try:
                            line = src.next_line()
                        except StopIteration:
                            burst_sent = None
                            break

                        wire = build_wire(line, tag_for_file, zeek_style)
                        if not send_one(wire):
                            raise RuntimeError("Fatal send error")

                        sent += 1
                        burst_sent += 1

                    if burst_sent is None:
                        break
                    if burst_delay:
                        time.sleep(burst_delay)
        finally:
            src.close()
        return sent

    try:
        if is_udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if not stop_at_eof:
            print("Error: Please use --stop-at-eof (this script is designed for file-by-file sending).")
            return

        print(f"Service mapping: zeek_defaults={len(DEFAULT_ZEEK_TAGS)} cli_overrides={len(cli_map)} fallback={'set' if service else 'none'}")
        for replay in range(1, count + 1):
            if is_tcp and not ensure_tcp_connected():
                return
            print(f"{replay}. replay files={len(files)}")
            for idx_fp, fp in enumerate(files):
                base = os.path.basename(fp)
                tag_used = pick_tag_for_file(fp)
                zeek_style = is_zeek_file(fp)
                t0 = time.perf_counter()
                n = send_file_once(fp)
                dt = time.perf_counter() - t0
                style = "zeek(no-colon)" if zeek_style else "normal"
                print(f"  - {base}: tag={tag_used} style={style} sent={n} elapsed={dt:.3f}s")
    finally:
        safe_close(sock)


# -------------------------
# CLI
# -------------------------
def parse_optional_args(argv) -> Tuple[str, str, float, bool, bool, Optional[str], Optional[str]]:
    fmt = "rfc3164"
    mode = "paced"
    burst_delay = 0.0
    tcp_append_newline = True
    stop_at_eof = False
    service = None
    service_map_arg = None

    i = 7
    while i < len(argv):
        a = argv[i]
        if a == "--format" and i + 1 < len(argv):
            fmt = argv[i + 1].strip().lower()
            i += 2
        elif a == "--mode" and i + 1 < len(argv):
            mode = argv[i + 1].strip().lower()
            i += 2
        elif a == "--burst-delay" and i + 1 < len(argv):
            burst_delay = float(argv[i + 1])
            i += 2
        elif a == "--tcp-no-newline":
            tcp_append_newline = False
            i += 1
        elif a == "--stop-at-eof":
            stop_at_eof = True
            i += 1
        elif a == "--service" and i + 1 < len(argv):
            service = argv[i + 1]
            i += 2
        elif a == "--service-map" and i + 1 < len(argv):
            service_map_arg = argv[i + 1]
            i += 2
        else:
            print(f"Error: Unknown/invalid option '{a}'")
            sys.exit(1)

    return fmt, mode, burst_delay, tcp_append_newline, stop_at_eof, service, service_map_arg


if __name__ == "__main__":
    if len(sys.argv) < 7:
        print("Usage: python3.9 loggen-new.py <ip> <port> <log_file|dir|glob> <count> <eps> <protocol> "
              "[--format rfc3164|raw] [--mode paced|burst] [--burst-delay seconds] "
              "[--tcp-no-newline] [--stop-at-eof] "
              "[--service fallbackName] [--service-map \"a.log=svcA,b.log=svcB\"]")
        print("  protocol: 1=TCP, 0=UDP")
        sys.exit(1)

    ip = sys.argv[1]
    try:
        port = int(sys.argv[2])
        input_path_or_pattern = sys.argv[3]
        count = int(sys.argv[4])
        eps = int(sys.argv[5])
        protocol = int(sys.argv[6])
    except ValueError:
        print("Error: Port, count, eps and protocol must be integers.")
        sys.exit(1)

    fmt, mode, burst_delay, tcp_append_newline, stop_at_eof, service, service_map_arg = parse_optional_args(sys.argv)

    send_log(ip, port, input_path_or_pattern, count, eps, protocol,
             fmt=fmt, mode=mode, burst_delay=burst_delay,
             tcp_append_newline=tcp_append_newline,
             stop_at_eof=stop_at_eof,
             service=service,
             service_map_arg=service_map_arg)
