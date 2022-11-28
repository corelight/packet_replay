#!/usr/bin/env python3

import argparse
import socket
import os
import time
import struct

from scapy.all import PcapReader


class PCAPPlayer(object):
    def __init__(self, filename, speed=1):
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
                if wait_time > 0.0001:
                    time.sleep(wait_time)
            except EOFError:
                return


class PCAPPlayerVXLAN(PCAPPlayer):
    def __init__(
        self, filename, target_ip, target_port=4789, speed=1, flags=0x8, vxlan_id=100
    ):
        super().__init__(filename, speed)
        self._target = (target_ip, target_port)
        self._socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        vxlan_id_bytes = [vxlan_id << 16 & 0xFF, vxlan_id << 8 & 0xFF, vxlan_id & 0xFF]
        self._vxlan_hdr = struct.pack("!B3x3Bx", flags, *vxlan_id_bytes)

    def _replay(self, pkt):
        self._socket.sendto(self._vxlan_hdr + bytes(pkt), self._target)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("pcap_file")
    parser.add_argument("-s", "--speed", type=float)
    parser.add_argument("-t", "--target-ip", type=str)

    args = parser.parse_args()

    player = PCAPPlayerVXLAN(args.pcap_file, target_ip=args.target_ip, speed=args.speed)
    player.replay_pcap()
