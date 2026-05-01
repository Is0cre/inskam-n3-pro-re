#!/usr/bin/env python3
import argparse
import curses
import os
import queue
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Optional

MAGIC = 0xFFEEFFEE

KEY_BINDINGS = [
    ("q", "Quit and stop sniffer"),
    ("i", "Fetch device info"),
    ("s", "Fetch status"),
    ("l", "LED on"),
    ("k", "LED off"),
    ("p", "Probe item 0x02"),
    ("c", "Send camera command (1,1,255)"),
    ("t", "Run TCP/RTSP/HTTP checks"),
    ("u", "Start UDP sniffer"),
    ("v", "Start UDP sniffer + VLC"),
    ("x", "Stop sniffer"),
    ("m", "One-shot monitor (info+status)"),
    ("r", "Reconnect Wi-Fi/socket"),
    ("a", "Scan placeholder (disabled)"),
    ("D", "Dangerous item scan (requires flag)"),
]


def key_help_line() -> str:
    return " | ".join(f"{k}:{desc}" for k, desc in KEY_BINDINGS)


def log_key_bindings(log: "EventLog"):
    log.add("key map loaded:")
    for key, desc in KEY_BINDINGS:
        log.add(f"  {key} -> {desc}")


def ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


class EventLog:
    def __init__(self, path: str, quiet: bool = False, max_lines: int = 2000):
        self.path = path
        self.quiet = quiet
        self.max_lines = max_lines
        self.lines = []
        self.lock = threading.Lock()

    def add(self, msg: str):
        line = f"[{ts()}] {msg}"
        with self.lock:
            self.lines.append(line)
            if len(self.lines) > self.max_lines:
                self.lines = self.lines[-self.max_lines :]
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        if not self.quiet:
            print(line)

    def snapshot(self):
        with self.lock:
            return list(self.lines)


@dataclass
class Reply:
    seq: int
    item: int
    op: int
    body_len: int
    body: bytes


class CamClient:
    def __init__(self, ip: str, port: int, local_ip: str, log: EventLog, timeout: float = 1.0):
        self.ip = ip
        self.port = port
        self.local_ip = local_ip
        self.log = log
        self.timeout = timeout
        self.seq = 1
        self.sock = None
        self.last_rx = 0.0
        self.lock = threading.Lock()
        self.reopen_socket()

    def build_packet(self, item: int, op: int, body: bytes = b"", seq: Optional[int] = None) -> bytes:
        if seq is None:
            seq = self.seq
            self.seq = (self.seq + 1) & 0xFFFF
            if self.seq == 0:
                self.seq = 1
        return struct.pack("<IHHHH", MAGIC, seq, item, op, len(body)) + body

    def send(self, item: int, op: int, body: bytes = b"") -> int:
        with self.lock:
            pkt = self.build_packet(item, op, body)
            seq = struct.unpack_from("<H", pkt, 4)[0]
            self.sock.sendto(pkt, (self.ip, self.port))
            return seq

    def recv(self, timeout: float = 0.2) -> Optional[Reply]:
        self.sock.settimeout(timeout)
        try:
            data, _ = self.sock.recvfrom(65535)
        except socket.timeout:
            return None
        self.last_rx = time.time()
        return self.decode(data)

    def request(self, item: int, op: int, body: bytes = b"", timeout: float = 1.0) -> Optional[Reply]:
        seq = self.send(item, op, body)
        deadline = time.time() + timeout
        while time.time() < deadline:
            rep = self.recv(timeout=0.2)
            if rep and rep.seq == seq:
                return rep
        return None

    def decode(self, data: bytes) -> Reply:
        if len(data) < 12:
            raise ValueError("packet too short")
        magic, seq, item, op, blen = struct.unpack_from("<IHHHH", data, 0)
        if magic != MAGIC:
            raise ValueError(f"bad magic 0x{magic:08x}")
        body = data[12:12 + blen]
        if len(body) != blen:
            raise ValueError("truncated body")
        return Reply(seq=seq, item=item, op=op, body_len=blen, body=body)

    def decode_op(self, op: int) -> str:
        return {0x0000: "OK", 0x0200: "UNSUPPORTED", 0x0300: "ALT_OK", 0x0301: "ACK"}.get(op, f"0x{op:04x}")

    def decode_status(self, body: bytes) -> dict:
        out = {"len": len(body), "raw_hex": body.hex()}
        if len(body) >= 3:
            out["possible_port_le16"] = struct.unpack_from("<H", body, 1)[0]
        return out

    def extract_ascii(self, body: bytes):
        parts = []
        cur = bytearray()
        for b in body:
            if 32 <= b <= 126:
                cur.append(b)
            else:
                if len(cur) >= 3:
                    parts.append(cur.decode("ascii", errors="ignore"))
                cur = bytearray()
        if len(cur) >= 3:
            parts.append(cur.decode("ascii", errors="ignore"))
        return parts

    def get_info(self):
        rep = self.request(0x01, 0)
        return rep

    def get_status(self):
        return self.request(0x0D, 0)

    def led(self, on: bool):
        body = bytes([1 if on else 0, 1]) + struct.pack("<I", 0xFF if on else 0)
        return self.request(0x0C, 1, body)

    def camera_cmd(self, action: int, target: int, value: int):
        return self.request(0x0C, 1, bytes([action & 0xFF, target & 0xFF]) + struct.pack("<I", value & 0xFFFFFFFF))

    def probe(self, item: int):
        return self.request(item, 0)

    def reopen_socket(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.local_ip, 0))
        self.sock.settimeout(self.timeout)
        self.log.add("UDP control socket reopened")

    def close(self):
        if self.sock:
            self.sock.close()


class Sniffer:
    def __init__(self, client: CamClient, listen_port: int, capture_file: str, log: EventLog):
        self.client = client
        self.listen_port = listen_port
        self.capture_file = capture_file
        self.log = log
        self.stop_evt = threading.Event()
        self.thread = None
        self.total = 0
        self.first_payload = threading.Event()

    @staticmethod
    def registration_bodies(port: int):
        return [
            struct.pack("<I", port),
            struct.pack(">I", port),
            struct.pack("<H", port),
            struct.pack(">H", port),
            b"\x01" + struct.pack("<I", port),
            b"\x02" + struct.pack("<I", port),
            b"\x03" + struct.pack("<I", port),
        ]

    def start(self, launch_vlc=False):
        if self.thread and self.thread.is_alive():
            self.log.add("sniffer already running")
            return
        self.stop_evt.clear()
        self.first_payload.clear()
        self.thread = threading.Thread(target=self._run, args=(launch_vlc,), daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_evt.set()

    def _run(self, launch_vlc: bool):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        sock.bind((self.client.local_ip, self.listen_port))
        self.log.add(f"sniffer bound UDP {self.listen_port}")
        for b in self.registration_bodies(self.listen_port):
            rep = self.client.request(0x0B, 0, b, timeout=0.8)
            self.log.add(f"register 0x0B body={b.hex()} -> {self.client.decode_op(rep.op) if rep else 'no-reply'}")
        st = self.client.get_status()
        if st:
            self.log.add(f"status after register: {self.client.decode_status(st.body)}")
        vlc = None
        start = time.time()
        with open(self.capture_file, "ab") as cap:
            while not self.stop_evt.is_set():
                try:
                    data, src = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                self.total += len(data)
                if not self.first_payload.is_set():
                    self.first_payload.set()
                    if launch_vlc:
                        try:
                            vlc = subprocess.Popen(["vlc", "-", "--demux", "h264"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            self.log.add("VLC launched after first payload")
                        except Exception as e:
                            self.log.add(f"VLC launch failed: {e}")
                cap.write(data)
                prefix = data[:4].hex()
                kind = "unknown"
                if data.startswith(b"\x00\x00\x00\x01"):
                    kind = "H264 Annex-B"
                elif data.startswith(b"\xff\xd8"):
                    kind = "JPEG"
                elif data[:1] == b"\x47":
                    kind = "possible MPEG-TS"
                rate = self.total / max(time.time() - start, 0.001)
                self.log.add(f"udp {len(data)}B from {src[0]}:{src[1]} prefix={prefix} type={kind} total={self.total} rate={rate:.1f}B/s")
                if vlc and vlc.stdin:
                    try:
                        vlc.stdin.write(data)
                        vlc.stdin.flush()
                    except Exception:
                        pass
        sock.close()
        if vlc and vlc.stdin:
            vlc.stdin.close()
        self.log.add("sniffer stopped")


def is_wifi_active(ssid: str) -> bool:
    try:
        out = subprocess.check_output(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"], text=True, timeout=3)
        for line in out.splitlines():
            if not line.strip():
                continue
            name = line.split(":", 1)[0]
            if name == ssid:
                return True
    except Exception:
        return False
    return False


def connect_wifi(ssid: str, log: EventLog):
    try:
        subprocess.check_call(["nmcli", "connection", "up", ssid], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=15)
        log.add(f"WiFi connected: {ssid}")
    except Exception as e:
        log.add(f"WiFi connect failed {ssid}: {e}")


def tcp_check(ip: str, log: EventLog):
    ports = [554, 8554, 10554, 80, 81, 8000, 8080, 8888]
    for p in ports:
        s = socket.socket()
        s.settimeout(0.6)
        ok = False
        try:
            s.connect((ip, p))
            ok = True
        except OSError:
            pass
        if ok:
            if p in [554, 8554, 10554]:
                for path in ["/", "/live", "/stream", "/h264"]:
                    req = f"OPTIONS rtsp://{ip}:{p}{path} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode()
                    try:
                        s.sendall(req)
                        resp = s.recv(128)
                        log.add(f"RTSP {p}{path} -> {resp[:40]!r}")
                    except OSError:
                        pass
            else:
                try:
                    s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
                    resp = s.recv(128)
                    log.add(f"HTTP {p} open -> {resp[:40]!r}")
                except OSError:
                    log.add(f"HTTP {p} open no response")
        else:
            log.add(f"TCP {p} closed")
        s.close()


def run_tui(stdscr, args):
    curses.curs_set(0)
    stdscr.nodelay(True)
    log = EventLog(args.log_file, quiet=args.quiet)
    log_key_bindings(log)
    if not args.no_wifi:
        active = is_wifi_active(args.wifi)
        if args.force_wifi or not active:
            connect_wifi(args.wifi, log)
        else:
            log.add(f"WiFi already active: {args.wifi}")
    client = CamClient(args.ip, args.port, args.local_ip, log)
    sniffer = Sniffer(client, args.listen_port, args.capture, log)
    info_ascii = []
    status = {}

    def maint():
        lastk = lasts = lasti = lastw = 0.0
        while True:
            now = time.time()
            try:
                if args.maintain and now - lastk >= args.keepalive_interval:
                    client.request(0x0B, 0, b"", timeout=0.5)
                    lastk = now
                if args.maintain and now - lasts >= args.status_interval:
                    rep = client.get_status()
                    if rep:
                        nonlocal status
                        status = client.decode_status(rep.body)
                    lasts = now
                if args.maintain and now - lasti >= args.info_interval:
                    rep = client.get_info()
                    if rep:
                        nonlocal info_ascii
                        info_ascii = client.extract_ascii(rep.body)
                    lasti = now
                if args.maintain and (not args.no_wifi) and now - lastw >= args.wifi_check_interval:
                    if not is_wifi_active(args.wifi):
                        log.add("WiFi dropped; reconnecting and reopening socket")
                        connect_wifi(args.wifi, log)
                        client.reopen_socket()
                    lastw = now
                while True:
                    r = client.recv(timeout=0.01)
                    if r is None:
                        break
                time.sleep(0.05)
            except Exception as e:
                log.add(f"maintainer exception: {e}; reopening socket")
                client.reopen_socket()
                time.sleep(0.3)

    threading.Thread(target=maint, daemon=True).start()
    if not args.no_start_info:
        r = client.get_info()
        if r:
            info_ascii = client.extract_ascii(r.body)

    while True:
        h, w = stdscr.getmaxyx()
        stdscr.erase()
        last_rx_age = "never" if client.last_rx == 0 else f"{time.time()-client.last_rx:.1f}s"
        hdr = f"INSKAM research tool | {args.ip}:{args.port} | wifi={args.wifi} | maintain={args.maintain} | last_rx={last_rx_age}"
        try:
            stdscr.addnstr(0, 0, hdr, max(1, w - 1))
            stdscr.addnstr(1, 0, "Keys: q i s l k p c t u v x m r a D", max(1, w - 1))
            stdscr.addnstr(2, 0, key_help_line(), max(1, w - 1))
            mid = max(30, w // 2)
            stdscr.addnstr(3, 0, "Device/Status", mid - 1)
            for idx, s in enumerate(info_ascii[: max(1, h - 8)]):
                stdscr.addnstr(4 + idx, 0, s, mid - 1)
            stdscr.addnstr(min(h - 3, 4 + len(info_ascii)), 0, f"status={status}", mid - 1)
            stdscr.addnstr(3, mid, "Log", w - mid - 1)
            logs = log.snapshot()[-max(1, h - 5):]
            for i, line in enumerate(logs):
                stdscr.addnstr(4 + i, mid, line, w - mid - 1)
        except curses.error:
            pass
        stdscr.refresh()

        ch = stdscr.getch()
        if ch == -1:
            time.sleep(0.05)
            continue
        key = chr(ch) if ch < 256 else ""
        if key == "q":
            sniffer.stop()
            break
        elif key == "i":
            rep = client.get_info(); log.add(f"info -> {client.decode_op(rep.op) if rep else 'no-reply'}")
            if rep: info_ascii = client.extract_ascii(rep.body)
        elif key == "s":
            rep = client.get_status(); log.add(f"status -> {client.decode_status(rep.body) if rep else 'no-reply'}")
            if rep: status = client.decode_status(rep.body)
        elif key == "l":
            rep = client.led(True); log.add(f"LED on -> {rep.body.hex() if rep else 'no-reply'}")
        elif key == "k":
            rep = client.led(False); log.add(f"LED off -> {rep.body.hex() if rep else 'no-reply'}")
        elif key == "p":
            rep = client.probe(0x02); log.add(f"probe 0x02 -> len={rep.body_len if rep else 0} op={client.decode_op(rep.op) if rep else 'none'}")
        elif key == "c":
            rep = client.camera_cmd(1, 1, 255); log.add(f"camera cmd -> {rep.body.hex() if rep else 'no-reply'}")
        elif key == "t":
            tcp_check(args.ip, log)
        elif key == "u":
            sniffer.start(launch_vlc=False)
        elif key == "v":
            sniffer.start(launch_vlc=True)
        elif key == "x":
            sniffer.stop(); log.add("sniffer stop requested")
        elif key == "m":
            repi = client.get_info(); reps = client.get_status()
            log.add(f"monitor once: info={client.decode_op(repi.op) if repi else 'no'} status={client.decode_status(reps.body) if reps else 'no'}")
        elif key == "r":
            if not args.no_wifi:
                connect_wifi(args.wifi, log)
            client.reopen_socket()
        elif key == "a":
            log.add("scan disabled because firmware resets")
        elif key == "D":
            if not args.enable_dangerous:
                log.add("dangerous mode blocked; rerun with --enable-dangerous")
            else:
                log.add("DANGEROUS LAB MODE ENABLED: scanning items 0x00..0x1f op=0 slowly")
                misses = 0
                for item in range(0x20):
                    rep = client.request(item, 0, b"", timeout=0.8)
                    if rep is None:
                        misses += 1
                        log.add(f"danger item 0x{item:02x} -> no-reply")
                    else:
                        misses = 0
                        log.add(f"danger item 0x{item:02x} -> op={client.decode_op(rep.op)} len={rep.body_len}")
                    if misses >= 6:
                        log.add("danger scan stopping after repeated no-reply")
                        break
                    time.sleep(args.dangerous_delay)


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="192.168.1.1")
    ap.add_argument("--port", type=int, default=10005)
    ap.add_argument("--local-ip", default="0.0.0.0")
    ap.add_argument("--wifi", default="UseeEar-37f1e")
    ap.add_argument("--no-wifi", action="store_true")
    ap.add_argument("--force-wifi", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--listen-port", type=int, default=20000)
    ap.add_argument("--capture", default="capture.bin")
    ap.add_argument("--log-file", default="cam_tui.log")
    ap.add_argument("--no-start-info", action="store_true")
    ap.add_argument("--maintain", dest="maintain", action="store_true", default=True)
    ap.add_argument("--no-maintain", dest="maintain", action="store_false")
    ap.add_argument("--keepalive-interval", type=float, default=1.0)
    ap.add_argument("--status-interval", type=float, default=5.0)
    ap.add_argument("--info-interval", type=float, default=15.0)
    ap.add_argument("--wifi-check-interval", type=float, default=10.0)
    ap.add_argument("--enable-dangerous", action="store_true")
    ap.add_argument("--dangerous-delay", type=float, default=2.0)
    return ap.parse_args()


if __name__ == "__main__":
    args = parse_args()
    curses.wrapper(run_tui, args)
