#!/usr/bin/env python3
import socket
import time
import sys
from typing import Optional


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
                   severity: int = 6) -> str:
    pri = calc_pri(facility, severity)
    ts = rfc3164_timestamp()
    msg = message.rstrip("\r\n")
    return f"<{pri}>{ts} {hostname} {tag}: {msg}"

def format_raw(message: str) -> str:
    return message.rstrip("\r\n")


# -------------------------
# Streaming file reader (no big memory usage)
# -------------------------
class StreamingLineSource:
    """
    Reads lines without loading file into memory.

    stop_at_eof=True:
      - raises StopIteration at EOF (send file once then stop)
    stop_at_eof=False:
      - cycles back to start at EOF (repeat forever)
    """
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

        # EOF reached
        if self.stop_at_eof:
            raise StopIteration

        # cycle mode
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
    s.settimeout(None)  # blocking for sendall()
    return s

def safe_close(sock: Optional[socket.socket]):
    if sock is None:
        return
    try:
        sock.close()
    except Exception:
        pass


# -------------------------
# Main sender
# -------------------------
def send_log(ip: str,
             port: int,
             file_path: str,
             count: int,
             eps: int,
             protocol: int,
             facility: int = 1,
             severity: int = 6,
             tag: str = "trafficGenerator",
             hostname: Optional[str] = None,
             tcp_retries: int = 10,
             tcp_backoff_start: float = 0.25,
             tcp_backoff_max: float = 3.0,
             fmt: str = "rfc3164",          # "rfc3164" or "raw"
             mode: str = "paced",           # "paced" or "burst"
             burst_delay: float = 0.0,      # seconds (burst mode)
             tcp_append_newline: bool = True,
             stop_at_eof: bool = False):
    """
    IMPORTANT SEMANTICS:
      - If stop_at_eof is True:
          count = number of times to send the WHOLE file
          (each replay starts from beginning and stops at EOF)
          paced mode: eps = messages/sec continuously until EOF
          burst mode: eps = messages per burst until EOF
      - If stop_at_eof is False (cycle):
          count/mode behave like earlier versions (count iterations),
          file will repeat forever (by cycling).
    """
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

    sock = None
    is_tcp = (protocol == 1)
    is_udp = (protocol == 0)

    if not (is_tcp or is_udp):
        print("Error: Invalid protocol. Use 1 for TCP or 0 for UDP.")
        return

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

    def build_wire(line: str) -> bytes:
        if fmt == "rfc3164":
            out = format_rfc3164(line, hostname, tag, facility, severity)
        else:
            out = format_raw(line)

        # simple TCP syslog framing: newline-delimited (commonly expected)
        if is_tcp and tcp_append_newline:
            out += "\n"

        return out.encode("utf-8", errors="replace")

    def send_one(wire: bytes) -> bool:
        """
        Returns True if sent (possibly after reconnect retry), False if fatal.
        """
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
                # retry once after reconnect
                try:
                    sock.sendall(wire)
                    return True
                except Exception as e2:
                    print(f"\nError: TCP resend after reconnect failed: {e2}")
                    return False
            else:
                # UDP: count as error but keep going
                return True

    try:
        if is_udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if stop_at_eof:
            # NEW: count means "replay whole file count times"
            total_sent = 0
            total_errors = 0
            overall_start = time.perf_counter()

            for replay in range(1, count + 1):
                if is_tcp and not ensure_tcp_connected():
                    return

                src = StreamingLineSource(file_path, stop_at_eof=True)
                sent = 0
                errors = 0

                print(f"{replay}.", end="")

                if mode == "paced":
                    # continuous pacing: eps messages per second until EOF
                    interval = 1.0 / float(eps)
                    next_send = time.perf_counter()

                    start = time.perf_counter()
                    while True:
                        # pace
                        now = time.perf_counter()
                        if now < next_send:
                            time.sleep(next_send - now)

                        try:
                            line = src.next_line()
                        except StopIteration:
                            break
                        except Exception as e:
                            print(f"\nError reading log file: {e}")
                            return

                        wire = build_wire(line)
                        ok = send_one(wire)
                        if not ok:
                            return

                        sent += 1
                        next_send += interval

                    elapsed = time.perf_counter() - start
                    print(f" mode=paced rate={eps}/s sent={sent} elapsed={elapsed:.3f}s errors={errors} (EOF)")

                else:
                    # burst mode until EOF
                    start = time.perf_counter()
                    while True:
                        burst_sent = 0
                        while burst_sent < eps:
                            try:
                                line = src.next_line()
                            except StopIteration:
                                # finished file
                                burst_sent = None
                                break
                            except Exception as e:
                                print(f"\nError reading log file: {e}")
                                return

                            wire = build_wire(line)
                            ok = send_one(wire)
                            if not ok:
                                return

                            sent += 1
                            burst_sent += 1

                        if burst_sent is None:
                            break  # EOF reached

                        if burst_delay:
                            time.sleep(burst_delay)

                    elapsed = time.perf_counter() - start
                    print(f" mode=burst burst={eps} sent={sent} elapsed={elapsed:.3f}s errors={errors} (EOF)")

                src.close()
                total_sent += sent
                total_errors += errors

            overall_elapsed = time.perf_counter() - overall_start
            print(f"TOTAL replays={count} sent={total_sent} errors={total_errors} elapsed={overall_elapsed:.3f}s")
            return

        # If stop_at_eof is False: keep prior behavior (count iterations)
        # count meaning:
        # - paced mode: count = number of 1-second windows
        # - burst mode: count = number of bursts
        src = StreamingLineSource(file_path, stop_at_eof=False)

        for idx in range(count):
            print(f"{idx + 1}.", end="")
            if is_tcp and not ensure_tcp_connected():
                return

            sent = 0
            errors = 0

            if mode == "paced":
                interval = 1.0 / float(eps)
                start = time.perf_counter()
                deadline = start + 1.0
                next_send = start

                while sent < eps:
                    now = time.perf_counter()
                    if now < next_send:
                        time.sleep(next_send - now)

                    line = src.next_line()
                    wire = build_wire(line)
                    ok = send_one(wire)
                    if not ok:
                        return

                    sent += 1
                    next_send += interval

                    if time.perf_counter() >= deadline:
                        break

                while sent < eps:
                    line = src.next_line()
                    wire = build_wire(line)
                    ok = send_one(wire)
                    if not ok:
                        return
                    sent += 1

                elapsed = time.perf_counter() - start
                remaining = 1.0 - elapsed
                if remaining > 0:
                    time.sleep(remaining)

                print(f" mode=paced eps={eps} sent={sent} elapsed={elapsed:.3f}s errors={errors}")

            else:
                start = time.perf_counter()
                for _ in range(eps):
                    line = src.next_line()
                    wire = build_wire(line)
                    ok = send_one(wire)
                    if not ok:
                        return
                    sent += 1

                elapsed = time.perf_counter() - start
                print(f" mode=burst burst={eps} sent={sent} elapsed={elapsed:.3f}s errors={errors}")

                if burst_delay and idx != count - 1:
                    time.sleep(burst_delay)

        src.close()

    finally:
        safe_close(sock)


# -------------------------
# CLI
# -------------------------
def parse_optional_args(argv):
    """
    Backward compatible:
      python trafficGenerator.py <ip> <port> <log_file> <count> <eps> <protocol>
         [--format rfc3164|raw]
         [--mode paced|burst]
         [--burst-delay seconds]
         [--tcp-no-newline]
         [--stop-at-eof]
    """
    fmt = "rfc3164"
    mode = "paced"
    burst_delay = 0.0
    tcp_append_newline = True
    stop_at_eof = False

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
        else:
            print(f"Error: Unknown/invalid option '{a}'")
            sys.exit(1)

    return fmt, mode, burst_delay, tcp_append_newline, stop_at_eof


if __name__ == "__main__":
    if len(sys.argv) < 7:
        print("Usage: python3.9 trafficGenerator.py <ip> <port> <log_file> <count> <eps> <protocol> "
              "[--format rfc3164|raw] [--mode paced|burst] [--burst-delay seconds] "
              "[--tcp-no-newline] [--stop-at-eof]")
        print("  protocol: 1=TCP, 0=UDP")
        sys.exit(1)

    ip = sys.argv[1]
    try:
        port = int(sys.argv[2])
        file_path = sys.argv[3]
        count = int(sys.argv[4])
        eps = int(sys.argv[5])
        protocol = int(sys.argv[6])
    except ValueError:
        print("Error: Port, count, eps and protocol must be integers.")
        sys.exit(1)

    fmt, mode, burst_delay, tcp_append_newline, stop_at_eof = parse_optional_args(sys.argv)

    send_log(ip, port, file_path, count, eps, protocol,
             fmt=fmt, mode=mode, burst_delay=burst_delay,
             tcp_append_newline=tcp_append_newline,
             stop_at_eof=stop_at_eof)