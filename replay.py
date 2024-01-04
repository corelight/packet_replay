#!/usr/bin/env python3

import argparse
import os
import sys
import socket
import struct
import time

from scapy.all import PcapReader, Ether, IP, UDP, Raw


class PCAPPlayer(object):
    def __init__(self, filename, speed=1.0, insert_log=False, pcap_id=0):
        if not os.path.isfile(filename):
            raise FileNotFoundError(f"Path {filename} does not exist or is not file")
        with open(filename, "rb") as f:
            # fail early if we can't read the file for some reason
            f.read(1)
        self.filename = filename
        self.speed = 1.0 / speed
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
        packet /= IP(src='0.0.0.0', dst='192.0.2.0')
        packet /= UDP(dport=514, sport=self.pcap_id % 65536)
        packet /= Raw(load=payload)

        return packet

    def replay_pcap(self):
        reader = PcapReader(self.filename)
        pkt = reader.read_packet()

        replay_start = time.time()
        pkt_start = pkt.time
        send_at = 0

        if self.insert_log:
            # reopen file since I don't see a way to seek(0)
            del reader
            reader = PcapReader(self.filename)

            pkt = self.get_syslog_pkt()

        while pkt:
            self._replay(pkt)

            try:
                pkt = reader.read_packet()
                send_at = self.speed * (pkt.time - pkt_start) + replay_start
                curr_time = time.time()
                wait_time = send_at - curr_time
                wait_time = float(wait_time)
                if wait_time > 0.0001:
                    time.sleep(wait_time)
            except EOFError:
                return


class PCAPPlayerVXLAN(PCAPPlayer):
    def __init__(
        self, filename, target_ip, target_port=4789, speed=1.0, flags=0x8, vxlan_id=100, **kw
    ):
        super().__init__(filename, speed, **kw)
        self._target = (target_ip, target_port)
        self._socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        vxlan_id_bytes = [vxlan_id >> 16 & 0xFF, vxlan_id >> 8 & 0xFF, vxlan_id & 0xFF]
        self._vxlan_hdr = struct.pack("!B3x3Bx", flags, *vxlan_id_bytes)

    def _replay(self, pkt):
        self._socket.sendto(self._vxlan_hdr + bytes(pkt), self._target)


class PCAPPlayerGENEVE(PCAPPlayer):
    def __init__(
        self, filename, target_ip, target_port=6081, speed=1.0, flags=0x00, vni=100, options=b'', **kw
    ):
        super().__init__(filename, speed, **kw)
        self._target = (target_ip, target_port)
        self._socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        version = 0
        protocol_type = 0x6558  # Transparent Ethernet bridging
        length = len(options)
        if length & 0x3:
            raise ValueError("Options length must be a multiple of 4 bytes")
        hlen = length >> 2
        if hlen > 0x3F:
            raise ValueError("options exceeds maximum length")
        vni_bytes = [vni >> 16 & 0xFF, vni >> 8 & 0xFF, vni & 0xFF]
        vl = ((version & 0x3) << 6) | (hlen & 0x3f)
        self._geneve_hdr = struct.pack(f"!BBH3Bx{length}s", vl, flags, protocol_type, *vni_bytes, options)

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-l", "--insert-log", action="store_true", default=False)

    parser.add_argument("pcap_file")
    parser.add_argument("-s", "--speed", type=float, default=1.0)

    subparsers = parser.add_subparsers(dest="output_type")
    subparsers.required = True

    parser_vxlan = subparsers.add_parser("vxlan")
    parser_vxlan.add_argument("-t", "--target-ip", type=str)

    parser_vxlan = subparsers.add_parser("geneve")
    parser_vxlan.add_argument("-t", "--target-ip", type=str)

    parser_packet = subparsers.add_parser("packet")
    parser_packet.add_argument("-i", "--interface", type=str)

    args = parser.parse_args()
    if args.output_type == "vxlan":
        player = PCAPPlayerVXLAN(
            args.pcap_file, target_ip=args.target_ip, speed=args.speed, insert_log=args.insert_log
        )
    elif args.output_type == "geneve":
        player = PCAPPlayerGENEVE(
            args.pcap_file, target_ip=args.target_ip, speed=args.speed, insert_log=args.insert_log
        )
    elif args.output_type == "packet":
        player = PCAPPlayerPacket(
            args.pcap_file, interface=args.interface, speed=args.speed, insert_log=args.insert_log
        )

    player.replay_pcap()
