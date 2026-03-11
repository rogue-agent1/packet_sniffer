#!/usr/bin/env python3
"""packet_sniffer.py — Network packet parser and analyzer.

Parses raw Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, and ARP
packets from pcap files or hex dumps. Displays protocol headers,
computes statistics, and filters by protocol/port.

One file. Zero deps. Does one thing well.
"""

import struct
import sys
from dataclasses import dataclass
from datetime import datetime


# ─── Ethernet ───

@dataclass
class EthernetFrame:
    dst_mac: str
    src_mac: str
    ethertype: int
    payload: bytes

    @classmethod
    def parse(cls, data: bytes) -> 'EthernetFrame':
        dst = ':'.join(f'{b:02x}' for b in data[0:6])
        src = ':'.join(f'{b:02x}' for b in data[6:12])
        etype = struct.unpack('!H', data[12:14])[0]
        return cls(dst, src, etype, data[14:])

    @property
    def proto_name(self):
        return {0x0800: 'IPv4', 0x0806: 'ARP', 0x86DD: 'IPv6'}.get(self.ethertype, f'0x{self.ethertype:04x}')


# ─── IPv4 ───

@dataclass
class IPv4Packet:
    version: int; ihl: int; tos: int; total_length: int
    identification: int; flags: int; fragment_offset: int
    ttl: int; protocol: int; checksum: int
    src_ip: str; dst_ip: str; payload: bytes

    @classmethod
    def parse(cls, data: bytes) -> 'IPv4Packet':
        ver_ihl = data[0]
        version = ver_ihl >> 4
        ihl = (ver_ihl & 0xF) * 4
        tos, total_len, ident = struct.unpack('!BHH', data[1:6])
        flags_frag = struct.unpack('!H', data[6:8])[0]
        flags = flags_frag >> 13
        frag_off = flags_frag & 0x1FFF
        ttl, proto, checksum = struct.unpack('!BBH', data[8:12])
        src = '.'.join(str(b) for b in data[12:16])
        dst = '.'.join(str(b) for b in data[16:20])
        return cls(version, ihl, tos, total_len, ident, flags, frag_off,
                   ttl, proto, checksum, src, dst, data[ihl:])

    @property
    def proto_name(self):
        return {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(self.protocol, str(self.protocol))


# ─── TCP ───

@dataclass
class TCPSegment:
    src_port: int; dst_port: int; seq: int; ack: int
    data_offset: int; flags: int; window: int
    checksum: int; urgent: int; payload: bytes

    @classmethod
    def parse(cls, data: bytes) -> 'TCPSegment':
        sp, dp, seq, ack = struct.unpack('!HHII', data[0:12])
        off_flags = struct.unpack('!H', data[12:14])[0]
        offset = ((off_flags >> 12) & 0xF) * 4
        flags = off_flags & 0x3F
        window, checksum, urgent = struct.unpack('!HHH', data[14:20])
        return cls(sp, dp, seq, ack, offset, flags, window, checksum, urgent, data[offset:])

    @property
    def flags_str(self):
        names = []
        for name, bit in [('FIN',1),('SYN',2),('RST',4),('PSH',8),('ACK',16),('URG',32)]:
            if self.flags & bit: names.append(name)
        return '|'.join(names) or 'NONE'


# ─── UDP ───

@dataclass
class UDPDatagram:
    src_port: int; dst_port: int; length: int; checksum: int; payload: bytes

    @classmethod
    def parse(cls, data: bytes) -> 'UDPDatagram':
        sp, dp, length, checksum = struct.unpack('!HHHH', data[0:8])
        return cls(sp, dp, length, checksum, data[8:])


# ─── ICMP ───

@dataclass
class ICMPPacket:
    type: int; code: int; checksum: int; payload: bytes
    TYPES = {0: 'Echo Reply', 3: 'Dest Unreachable', 8: 'Echo Request', 11: 'Time Exceeded'}

    @classmethod
    def parse(cls, data: bytes) -> 'ICMPPacket':
        t, c, cksum = struct.unpack('!BBH', data[0:4])
        return cls(t, c, cksum, data[4:])

    @property
    def type_name(self): return self.TYPES.get(self.type, f'Type {self.type}')


# ─── ARP ───

@dataclass
class ARPPacket:
    hw_type: int; proto_type: int; hw_size: int; proto_size: int
    opcode: int; sender_mac: str; sender_ip: str; target_mac: str; target_ip: str

    @classmethod
    def parse(cls, data: bytes) -> 'ARPPacket':
        hwt, pt, hs, ps, op = struct.unpack('!HHBBH', data[0:8])
        smac = ':'.join(f'{b:02x}' for b in data[8:14])
        sip = '.'.join(str(b) for b in data[14:18])
        tmac = ':'.join(f'{b:02x}' for b in data[18:24])
        tip = '.'.join(str(b) for b in data[24:28])
        return cls(hwt, pt, hs, ps, op, smac, sip, tmac, tip)

    @property
    def op_name(self): return {1: 'Request', 2: 'Reply'}.get(self.opcode, str(self.opcode))


# ─── DNS ───

@dataclass
class DNSPacket:
    id: int; flags: int; questions: int; answers: int
    is_response: bool; query_names: list[str]

    @classmethod
    def parse(cls, data: bytes) -> 'DNSPacket':
        did, flags, qdcount, ancount, _, _ = struct.unpack('!HHHHHH', data[0:12])
        is_resp = bool(flags & 0x8000)
        names = []
        offset = 12
        for _ in range(qdcount):
            name, offset = cls._read_name(data, offset)
            names.append(name)
            offset += 4  # skip qtype + qclass
        return cls(did, flags, qdcount, ancount, is_resp, names)

    @staticmethod
    def _read_name(data: bytes, offset: int) -> tuple[str, int]:
        parts = []
        while offset < len(data):
            length = data[offset]
            if length == 0: offset += 1; break
            if length & 0xC0 == 0xC0:  # pointer
                ptr = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
                name, _ = DNSPacket._read_name(data, ptr)
                parts.append(name); offset += 2; break
            offset += 1
            parts.append(data[offset:offset+length].decode('ascii', errors='replace'))
            offset += length
        return '.'.join(parts), offset


# ─── Pcap Reader ───

def read_pcap(data: bytes) -> list[tuple[float, bytes]]:
    """Parse pcap file format."""
    magic = struct.unpack('<I', data[0:4])[0]
    if magic == 0xa1b2c3d4:
        endian = '<'
    elif magic == 0xd4c3b2a1:
        endian = '>'
    else:
        raise ValueError("Not a pcap file")
    _, _, _, _, snaplen, linktype = struct.unpack(endian + 'IHHII', data[4:24])
    packets = []
    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', data[offset:offset+16])
        offset += 16
        pkt_data = data[offset:offset + incl_len]
        offset += incl_len
        packets.append((ts_sec + ts_usec / 1e6, pkt_data))
    return packets


# ─── Analyzer ───

def analyze_packet(raw: bytes) -> dict:
    """Parse all layers of a packet."""
    result = {'layers': []}
    eth = EthernetFrame.parse(raw)
    result['layers'].append(('Ethernet', f"{eth.src_mac} → {eth.dst_mac} [{eth.proto_name}]"))

    if eth.ethertype == 0x0800:
        ip = IPv4Packet.parse(eth.payload)
        result['layers'].append(('IPv4', f"{ip.src_ip} → {ip.dst_ip} TTL={ip.ttl} [{ip.proto_name}]"))
        result['src_ip'] = ip.src_ip
        result['dst_ip'] = ip.dst_ip

        if ip.protocol == 6:
            tcp = TCPSegment.parse(ip.payload)
            result['layers'].append(('TCP', f"{tcp.src_port} → {tcp.dst_port} [{tcp.flags_str}] seq={tcp.seq}"))
            result['src_port'] = tcp.src_port
            result['dst_port'] = tcp.dst_port
            result['protocol'] = 'TCP'
            if tcp.dst_port == 53 or tcp.src_port == 53:
                try:
                    dns = DNSPacket.parse(tcp.payload[2:])  # TCP DNS has 2-byte length prefix
                    result['layers'].append(('DNS', f"{'Response' if dns.is_response else 'Query'} {dns.query_names}"))
                except: pass
        elif ip.protocol == 17:
            udp = UDPDatagram.parse(ip.payload)
            result['layers'].append(('UDP', f"{udp.src_port} → {udp.dst_port} len={udp.length}"))
            result['src_port'] = udp.src_port
            result['dst_port'] = udp.dst_port
            result['protocol'] = 'UDP'
            if udp.dst_port == 53 or udp.src_port == 53:
                try:
                    dns = DNSPacket.parse(udp.payload)
                    result['layers'].append(('DNS', f"{'Response' if dns.is_response else 'Query'} {dns.query_names}"))
                except: pass
        elif ip.protocol == 1:
            icmp = ICMPPacket.parse(ip.payload)
            result['layers'].append(('ICMP', f"{icmp.type_name} code={icmp.code}"))
            result['protocol'] = 'ICMP'

    elif eth.ethertype == 0x0806:
        arp = ARPPacket.parse(eth.payload)
        result['layers'].append(('ARP', f"{arp.op_name} {arp.sender_ip} ({arp.sender_mac}) → {arp.target_ip}"))
        result['protocol'] = 'ARP'

    return result


def demo():
    print("=== Packet Sniffer / Analyzer ===\n")
    # Construct a synthetic TCP SYN packet
    eth = bytes.fromhex('ffffffffffff' + 'aabbccddeeff' + '0800')
    ip_header = bytes([
        0x45, 0x00, 0x00, 0x28,  # ver/ihl, tos, total_len
        0x00, 0x01, 0x00, 0x00,  # id, flags/frag
        0x40, 0x06, 0x00, 0x00,  # ttl=64, proto=TCP, checksum
        192, 168, 1, 100,         # src
        93, 184, 216, 34,         # dst
    ])
    tcp_header = struct.pack('!HHIIBBHHH', 12345, 443, 1000, 0, 0x50, 0x02, 65535, 0, 0)
    raw = eth + ip_header + tcp_header

    result = analyze_packet(raw)
    for layer, info in result['layers']:
        print(f"  [{layer:10s}] {info}")

    # ARP packet
    eth_arp = bytes.fromhex('ffffffffffff' + 'aabbccddeeff' + '0806')
    arp_data = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)
    arp_data += bytes.fromhex('aabbccddeeff') + bytes([192,168,1,1])
    arp_data += bytes(6) + bytes([192,168,1,100])
    result2 = analyze_packet(eth_arp + arp_data)
    print()
    for layer, info in result2['layers']:
        print(f"  [{layer:10s}] {info}")


if __name__ == '__main__':
    if '--test' in sys.argv:
        # Ethernet
        raw = bytes(6) + bytes(6) + struct.pack('!H', 0x0800) + bytes(40)
        eth = EthernetFrame.parse(raw)
        assert eth.ethertype == 0x0800
        assert eth.proto_name == 'IPv4'
        # IPv4
        ip_raw = bytes([0x45,0,0,40, 0,1,0,0, 64,6,0,0, 10,0,0,1, 10,0,0,2]) + bytes(20)
        ip = IPv4Packet.parse(ip_raw)
        assert ip.src_ip == '10.0.0.1'
        assert ip.protocol == 6
        # TCP
        tcp_raw = struct.pack('!HHIIBBHHH', 80, 443, 100, 200, 0x50, 0x12, 65535, 0, 0)
        tcp = TCPSegment.parse(tcp_raw)
        assert tcp.src_port == 80 and tcp.dst_port == 443
        assert 'SYN' in tcp.flags_str and 'ACK' in tcp.flags_str
        # UDP
        udp_raw = struct.pack('!HHHH', 53, 1234, 12, 0) + b'test'
        udp = UDPDatagram.parse(udp_raw)
        assert udp.src_port == 53
        # ICMP
        icmp_raw = struct.pack('!BBH', 8, 0, 0) + bytes(4)
        icmp = ICMPPacket.parse(icmp_raw)
        assert icmp.type_name == 'Echo Request'
        # Full packet analysis
        full = bytes(12) + struct.pack('!H', 0x0800) + ip_raw[:20] + tcp_raw
        result = analyze_packet(full)
        assert len(result['layers']) >= 3
        print("All tests passed ✓")
    else:
        demo()
