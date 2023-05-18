#!/usr/bin/env python3

import argparse
import os
import socket
import struct
import time

from scapy.all import PcapReader


class PCAPPlayer(object):
    def __init__(self, filename, speed=1.0):
        if not os.path.isfile(filename):
            raise FileNotFoundError(f"Path {filename} does not exist or is not file")
        with open(filename, "rb") as f:
            # fail early if we can't read the file for some reason
            f.read(1)
        self.filename = filename
        self.speed = 1.0 / speed

    def replay_pcap(self):
        reader = PcapReader(self.filename)
        pkt = reader.read_packet()

        replay_start = time.time()
        pkt_start = pkt.time
        send_at = 0

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
        self, filename, target_ip, target_port=4789, speed=1.0, flags=0x8, vxlan_id=100
    ):
        super().__init__(filename, speed)
        self._target = (target_ip, target_port)
        self._socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        vxlan_id_bytes = [vxlan_id << 16 & 0xFF, vxlan_id << 8 & 0xFF, vxlan_id & 0xFF]
        self._vxlan_hdr = struct.pack("!B3x3Bx", flags, *vxlan_id_bytes)

    def _replay(self, pkt):
        self._socket.sendto(self._vxlan_hdr + bytes(pkt), self._target)


class PCAPPlayerPacket(PCAPPlayer):
    def __init__(self, filename, interface, speed=1.0):
        super().__init__(filename, speed)
        self._interface = interface
        self._socket = socket.socket(family=socket.AF_PACKET, type=socket.SOCK_RAW)
        self._socket.bind((self._interface, 0))

    def _replay(self, pkt):
        self._socket.send(bytes(pkt))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("pcap_file")
    parser.add_argument("-s", "--speed", type=float, default=1.0)

    subparsers = parser.add_subparsers(dest="output_type")
    subparsers.required = True

    parser_vxlan = subparsers.add_parser("vxlan")
    parser_vxlan.add_argument("-t", "--target-ip", type=str)

    parser_packet = subparsers.add_parser("packet")
    parser_packet.add_argument("-i", "--interface", type=str)

    args = parser.parse_args()
    if args.output_type == "vxlan":
        player = PCAPPlayerVXLAN(
            args.pcap_file, target_ip=args.target_ip, speed=args.speed
        )
    elif args.output_type == "packet":
        player = PCAPPlayerPacket(
            args.pcap_file, interface=args.interface, speed=args.speed
        )

    player.replay_pcap()
