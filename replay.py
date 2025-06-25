#!/usr/bin/env python3

import argparse
import binascii
import os
import sys
import socket
import struct
import time
from decimal import Decimal

from scapy.all import RawPcapReader, RawPcapNgReader, Ether, IP, UDP, Raw


def read_packet(reader):
    """Return packet with epoch time representing the time from the header in the pcap"""

    pkt, pkt_info = reader._read_packet()
    pkt_time = None

    if isinstance(reader, RawPcapNgReader):
        # do the NG thing
        if pkt_info.tshigh is not None:
            pkt_time = Decimal((pkt_info.tshigh << 32) + pkt_info.tslow) / pkt_info.tsresol
            return (pkt, pkt_time, pkt_info)

    # do the non-NG thing
    power = Decimal(10) ** Decimal(-9 if reader.nano else -6)
    pkt_time = Decimal(pkt_info.sec + power * pkt_info.usec)
    return (pkt, pkt_time, pkt_info)


class PCAPPlayer(object):
    def __init__(self, filename, speed=1.0, insert_log=False, pcap_id=0):
        if not os.path.isfile(filename):
            raise FileNotFoundError(f"Path {filename} does not exist or is not file")
        with open(filename, "rb") as f:
            # fail early if we can't read the file for some reason
            f.read(1)
        self.filename = filename
        self.speed = Decimal(1.0) / Decimal(speed)
        self.insert_log = insert_log
        self.pcap_id = pcap_id

    def get_syslog_pkt(self):
        facility = 23
        pri = 7
        prival = facility << 3 | pri
        timestamp = time.strftime("%b %d %H:%M:%S", time.gmtime())
        hostname = socket.gethostname()
        program = sys.argv[0]
        pid = os.getpid()
        message = f"filename: {self.filename} time_scaling: {self.speed}"

        payload = f"<{prival}>{timestamp} {hostname} {program}[{pid}]: {message}"

        packet = Ether(src="02:00:00:00:00:00", dst="fe:ff:ff:ff:ff:ff")
        packet /= IP(src="0.0.0.0", dst="192.0.2.0")
        packet /= UDP(dport=514, sport=self.pcap_id % 65536)
        packet /= Raw(load=payload)

        return bytes(packet)

    def replay_pcap(self):
        reader = RawPcapReader(self.filename)
        (pkt, pkt_time, pkt_info) = read_packet(reader)

        replay_start = Decimal(time.time())
        pkt_start = pkt_time
        send_at = 0

        # switch to raw packets to avoid all of the parsing shenanigans

        if self.insert_log:
            syslog_pkt = self.get_syslog_pkt()
            self._replay(syslog_pkt)

        while pkt:
            self._replay(pkt)

            try:
                (pkt, pkt_time, pkt_info) = read_packet(reader)
                send_at = self.speed * (pkt_time - pkt_start) + replay_start
                curr_time = Decimal(time.time())
                wait_time = send_at - curr_time
                wait_time = float(wait_time)
                if wait_time > 0.0001:
                    time.sleep(wait_time)
            except EOFError:
                return


class PCAPPlayerUDP(PCAPPlayer):
    def __init__(self, filename, target_ip, source_port, target_port, speed=1.0, **kw):
        super().__init__(filename, speed, **kw)
        self._target = (target_ip, target_port)
        self._socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        if source_port is not None:
            self._socket.bind(("0.0.0.0", source_port))

    def __del__(self):
        self._socket.close()


class PCAPPlayerVXLAN(PCAPPlayerUDP):
    def __init__(
        self,
        filename,
        target_ip,
        source_port=None,
        target_port=4789,
        speed=1.0,
        flags=0x8,
        vxlan_id=100,
        **kw,
    ):
        super().__init__(
            filename,
            target_ip=target_ip,
            source_port=source_port,
            target_port=target_port,
            speed=speed,
            **kw,
        )
        vxlan_id_bytes = [vxlan_id >> 16 & 0xFF, vxlan_id >> 8 & 0xFF, vxlan_id & 0xFF]
        self._vxlan_hdr = struct.pack("!B3x3Bx", flags, *vxlan_id_bytes)

    def _replay(self, pkt):
        self._socket.sendto(self._vxlan_hdr + bytes(pkt), self._target)


class PCAPPlayerGENEVE(PCAPPlayerUDP):
    def __init__(
        self,
        filename,
        target_ip,
        source_port=None,
        target_port=6081,
        speed=1.0,
        flags=0x00,
        vni=100,
        add_tag=False,
        options=None,
        **kw,
    ):
        super().__init__(
            filename,
            target_ip=target_ip,
            source_port=source_port,
            target_port=target_port,
            speed=speed,
            **kw,
        )
        version = 0
        protocol_type = 0x6558  # Transparent Ethernet bridging

        if not options:
            options = b""

        if add_tag:
            # TODO: this could do odd things with unicode, but doest't seem worth the
            # effort to fix it today
            tag_part = filename
            tag_byte_len = len(tag_part.encode())
            if tag_byte_len > 124:
                truncation_marker = "..."
                to_strip = tag_byte_len - 124 - len(truncation_marker)
                tag_part = truncation_marker + tag_part[to_strip:]
            options = build_geneve_option(0xFF72, 0x7F, tag_part.encode()) + options

        length = len(options)
        if length & 0x3:
            raise ValueError("Options length must be a multiple of 4 bytes")
        hlen = length >> 2
        if hlen > 0x3F:
            raise ValueError("options exceeds maximum length")
        vni_bytes = [vni >> 16 & 0xFF, vni >> 8 & 0xFF, vni & 0xFF]
        vl = ((version & 0x3) << 6) | (hlen & 0x3F)
        self._geneve_hdr = struct.pack(
            f"!BBH3Bx{length}s", vl, flags, protocol_type, *vni_bytes, options
        )

    def _replay(self, pkt):
        self._socket.sendto(self._geneve_hdr + bytes(pkt), self._target)


class PCAPPlayerPacket(PCAPPlayer):
    def __init__(self, filename, interface, speed=1.0, **kw):
        super().__init__(filename, speed, **kw)
        self._interface = interface
        self._socket = socket.socket(family=socket.AF_PACKET, type=socket.SOCK_RAW)
        self._socket.bind((self._interface, 0))

    def _replay(self, pkt):
        self._socket.send(bytes(pkt))


def build_geneve_options_hex(options):
    return b"".join(map(build_geneve_option_hex, options))


def build_geneve_option_hex(s):
    opt_class, opt_type, opt_val = s.split(":")
    opt_class = int(opt_class, base=16)
    opt_type = int(opt_type, base=16)
    opt_val = binascii.unhexlify(opt_val)

    return build_geneve_option(opt_class, opt_type, opt_val)


def build_geneve_option(opt_class, opt_type, opt_val):
    if opt_class > 0xFFFF:
        raise Exception("opt_class out of range")
    if opt_type > 0xFF:
        # technically, the first bit is the critical bit
        raise Exception("opt_type out of range")

    m = len(opt_val) % 4
    opt_pad = 4 - m if m else 0
    opt_val = opt_val + opt_pad * b"\0"

    opt_len = len(opt_val) // 4
    if (opt_len & 0x1F) != opt_len:
        # field is only 5 bits long
        raise Exception("opt_val is too long")

    option = struct.pack(f"!HBB{opt_len * 4}s", opt_class, opt_type, opt_len, opt_val)
    return option


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-l", "--insert-log", action="store_true", default=False)

    parser.add_argument("pcap_file")
    parser.add_argument("-s", "--speed", type=float, default=1.0)

    subparsers = parser.add_subparsers(dest="output_type")
    subparsers.required = True

    parser_vxlan = subparsers.add_parser("vxlan")
    parser_vxlan.add_argument("-t", "--target-ip", type=str)

    parser_geneve = subparsers.add_parser("geneve")
    parser_geneve.add_argument("-t", "--target-ip", type=str)
    parser_geneve.add_argument(
        "-T",
        "--add-tag",
        action="store_true",
        help="Add an experimental tag to the geneve header with (part of) the pcap name",
        default=False,
    )
    parser_geneve.add_argument(
        "-o",
        "--geneve-option",
        action="append",
        dest="geneve_options",
        help="<option_class_hex>:<option_type_hex>:<option_value_hex> -- "
        " option value will be null-padded on the right to a multiple of 4 bytes",
        type=str,
    )

    parser_packet = subparsers.add_parser("packet")
    parser_packet.add_argument("-i", "--interface", type=str)

    args = parser.parse_args()
    if args.output_type == "vxlan":
        player = PCAPPlayerVXLAN(
            args.pcap_file,
            target_ip=args.target_ip,
            speed=args.speed,
            insert_log=args.insert_log,
        )
    elif args.output_type == "geneve":
        opts = b""
        if args.geneve_options:
            opts = build_geneve_options_hex(args.geneve_options)
        player = PCAPPlayerGENEVE(
            args.pcap_file,
            target_ip=args.target_ip,
            speed=args.speed,
            add_tag=args.add_tag,
            options=opts,
            insert_log=args.insert_log,
        )
    elif args.output_type == "packet":
        player = PCAPPlayerPacket(
            args.pcap_file,
            interface=args.interface,
            speed=args.speed,
            insert_log=args.insert_log,
        )

    player.replay_pcap()
