#!/usr/local/bin/python3
import argparse
import ipaddress
import os
import re
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time


PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
IGMP_V2_REPORT = 0x16
IGMP_V2_LEAVE = 0x17
IPV4_ETHERTYPE = 0x0800
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
MAC_ADDRESS_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")


def checksum(payload):
    if len(payload) % 2:
        payload += b"\x00"
    total = sum(struct.unpack(f"!{len(payload) // 2}H", payload))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def read_exact(stream, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class PcapCapture:
    def __init__(self, interface, capture_filter):
        self.interface = interface
        self.capture_filter = capture_filter
        self.process = None
        self.endian = None
        self.start()

    def start(self):
        self.close()
        self.process = subprocess.Popen(
            [
                "tcpdump",
                "-B",
                "8192",
                "-U",
                "-n",
                "-i",
                self.interface,
                "-s",
                "0",
                "-w",
                "-",
                self.capture_filter,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        header = read_exact(self.process.stdout, 24)
        if header is None or header[:4] not in PCAP_MAGIC:
            self.close()
            raise RuntimeError(f"tcpdump on {self.interface} did not provide pcap output")
        self.endian = PCAP_MAGIC[header[:4]][0]

    def fileno(self):
        return self.process.stdout.fileno()

    def read_frame(self):
        header = read_exact(self.process.stdout, 16)
        if header is None:
            raise EOFError(f"tcpdump on {self.interface} ended")
        _, _, captured_length, _ = struct.unpack(f"{self.endian}IIII", header)
        frame = read_exact(self.process.stdout, captured_length)
        if frame is None:
            raise EOFError(f"tcpdump on {self.interface} ended")
        return frame

    def close(self):
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process = None


def ipv4_packet(frame):
    if len(frame) < 34:
        return None
    offset = 14
    ethertype = struct.unpack("!H", frame[12:14])[0]
    while ethertype in VLAN_ETHERTYPES:
        if len(frame) < offset + 4:
            return None
        ethertype = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        offset += 4
    if ethertype != IPV4_ETHERTYPE or len(frame) < offset + 20:
        return None
    packet = frame[offset:]
    version = packet[0] >> 4
    header_length = (packet[0] & 0x0F) * 4
    if version != 4 or header_length < 20 or len(packet) < header_length:
        return None
    total_length = struct.unpack("!H", packet[2:4])[0]
    if total_length < header_length or len(packet) < total_length:
        return None
    return packet[:total_length]


def interface_ipv4(interface):
    output = subprocess.check_output(["ifconfig", interface], text=True)
    match = re.search(r"^\s*inet\s+(\d+\.\d+\.\d+\.\d+)\b", output, re.MULTILINE)
    if not match:
        raise RuntimeError(f"no IPv4 address on {interface}")
    return match.group(1)


def is_iptv_group(address):
    return ipaddress.IPv4Address(address) in ipaddress.IPv4Network("233.0.0.0/8")


def mac_address(value):
    if not MAC_ADDRESS_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError("MAC address must use xx:xx:xx:xx:xx:xx format")
    return value.lower()


class IptvRelay:
    def __init__(self, wan, lan, stb_mac, group_ttl, leave_grace, query_interval):
        self.wan = wan
        self.lan = lan
        self.stb_mac = stb_mac.lower()
        self.group_ttl = group_ttl
        self.leave_grace = leave_grace
        self.query_interval = query_interval
        self.groups = {}
        self.pending_leaves = {}
        self.sequence = 1
        self.running = True
        self.report_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.report_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.forward_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.forward_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.forward_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
        self.forward_socket.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_IF,
            socket.inet_aton(interface_ipv4(self.lan)),
        )
        self.lan_address = interface_ipv4(self.lan)
        self.lan_capture = PcapCapture(
            self.lan,
            f"igmp and ether src {self.stb_mac}",
        )
        self.wan_capture = PcapCapture(
            self.wan,
            "udp and dst net 224.0.0.0/4",
        )
        self.selector = selectors.DefaultSelector()
        self.register_captures()
        self.forwarded_packets = 0
        self.last_stats = time.monotonic()
        self.last_query = 0

    def register_captures(self):
        self.selector.close()
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.lan_capture.fileno(), selectors.EVENT_READ, "lan")
        self.selector.register(self.wan_capture.fileno(), selectors.EVENT_READ, "wan")

    def send_igmp(self, group, message_type):
        source_address = interface_ipv4(self.wan)
        source = ipaddress.IPv4Address(source_address).packed
        group_address = ipaddress.IPv4Address(group).packed
        igmp = struct.pack("!BBH4s", message_type, 0, 0, group_address)
        igmp = struct.pack("!BBH4s", message_type, 0, checksum(igmp), group_address)
        destination = group_address if message_type == IGMP_V2_REPORT else ipaddress.IPv4Address("224.0.0.2").packed
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x46,
            0x88,
            32,
            self.sequence,
            0x4000,
            1,
            socket.IPPROTO_IGMP,
            0,
            source,
            destination,
        ) + b"\x94\x04\x00\x00"
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        self.report_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(source_address))
        self.report_socket.sendto(header + igmp, (socket.inet_ntoa(destination), 0))
        self.sequence = (self.sequence + 1) & 0xFFFF

    def send_general_query(self):
        source = ipaddress.IPv4Address(self.lan_address).packed
        destination = ipaddress.IPv4Address("224.0.0.1").packed
        igmp = struct.pack("!BBH4s", 0x11, 100, 0, b"\x00\x00\x00\x00")
        igmp = struct.pack("!BBH4s", 0x11, 100, checksum(igmp), b"\x00\x00\x00\x00")
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x46,
            0,
            32,
            self.sequence,
            0x4000,
            1,
            socket.IPPROTO_IGMP,
            0,
            source,
            destination,
        ) + b"\x94\x04\x00\x00"
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        self.report_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.lan_address))
        self.report_socket.sendto(header + igmp, ("224.0.0.1", 0))
        self.sequence = (self.sequence + 1) & 0xFFFF

    def process_lan_frame(self, frame):
        packet = ipv4_packet(frame)
        if packet is None or packet[9] != socket.IPPROTO_IGMP:
            return
        header_length = (packet[0] & 0x0F) * 4
        if len(packet) < header_length + 8:
            return
        message_type = packet[header_length]
        group = socket.inet_ntoa(packet[header_length + 4:header_length + 8])
        if not is_iptv_group(group):
            return
        if message_type == IGMP_V2_REPORT:
            self.groups[group] = time.monotonic() + self.group_ttl
            self.pending_leaves.pop(group, None)
            self.send_igmp(group, IGMP_V2_REPORT)
            print(f"join {group}", flush=True)
        elif message_type == IGMP_V2_LEAVE:
            if group in self.groups:
                self.pending_leaves[group] = time.monotonic() + self.leave_grace
                print(f"leave pending {group}", flush=True)

    def process_wan_frame(self, frame):
        packet = ipv4_packet(frame)
        if packet is None or packet[9] != socket.IPPROTO_UDP:
            return
        destination = socket.inet_ntoa(packet[16:20])
        if destination not in self.groups:
            return
        self.forward_socket.sendto(packet, (destination, 0))
        self.forwarded_packets += 1

    def expire_groups(self):
        now = time.monotonic()
        if now - self.last_query >= self.query_interval:
            self.send_general_query()
            self.last_query = now
        for group, deadline in list(self.pending_leaves.items()):
            if deadline <= now:
                self.pending_leaves.pop(group, None)
                if group in self.groups:
                    self.groups.pop(group, None)
                    self.send_igmp(group, IGMP_V2_LEAVE)
                    print(f"leave {group}", flush=True)
        for group, expiry in list(self.groups.items()):
            if expiry <= now:
                self.groups.pop(group, None)
                self.pending_leaves.pop(group, None)
                self.send_igmp(group, IGMP_V2_LEAVE)
                print(f"expired {group}", flush=True)
        if now - self.last_stats >= 15:
            print(
                f"active_groups={len(self.groups)} forwarded_packets={self.forwarded_packets}",
                flush=True,
            )
            self.forwarded_packets = 0
            self.last_stats = now

    def restart_capture(self, name):
        capture = self.lan_capture if name == "lan" else self.wan_capture
        capture.start()
        self.register_captures()
        print(f"restarted {name} capture", flush=True)

    def run(self):
        self.send_general_query()
        self.last_query = time.monotonic()
        while self.running:
            for key, _ in self.selector.select(timeout=1):
                name = key.data
                capture = self.lan_capture if name == "lan" else self.wan_capture
                try:
                    frame = capture.read_frame()
                    if name == "lan":
                        self.process_lan_frame(frame)
                    else:
                        self.process_wan_frame(frame)
                except EOFError:
                    self.restart_capture(name)
            self.expire_groups()

    def close(self):
        self.lan_capture.close()
        self.wan_capture.close()
        self.selector.close()
        self.report_socket.close()
        self.forward_socket.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wan", default="igc0")
    parser.add_argument("--lan", default="igc1")
    parser.add_argument("--stb-mac", required=True, type=mac_address)
    parser.add_argument("--group-ttl", type=int, default=300)
    parser.add_argument("--leave-grace", type=int, default=5)
    parser.add_argument("--query-interval", type=int, default=125)
    args = parser.parse_args()

    relay = IptvRelay(
        args.wan,
        args.lan,
        args.stb_mac,
        args.group_ttl,
        args.leave_grace,
        args.query_interval,
    )

    def stop_handler(_signum, _frame):
        relay.running = False

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    try:
        relay.run()
    finally:
        relay.close()


if __name__ == "__main__":
    main()
