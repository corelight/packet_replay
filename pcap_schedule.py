#!/usr/bin/env python3

import logging
import math
import os
import pprint
from multiprocessing import Process

import scapy.utils

logger = logging.getLogger("pcap_schedule")


class PCAPScheduler(object):
    def __init__(self, max_duration=None, insert_log=False):
        if max_duration is None:
            # this is more of a rough estimate
            max_duration = 6 * 60 * 60  # 6 hours
        self.max_duration = max_duration
        self.insert_log = insert_log
        self.pcaps = {}
        self.threads = None
        self.current_pcap_id = 0

    def get_pcap_info(self, filename):
        logger.debug(f"get info for {filename}")
        self.current_pcap_id += 1
        pcap_info = {
            "filename": filename,
            "packets": 0,
            "bytes": 0,
            "start": None,
            "end": None,
            "duration": None,
            "id": self.current_pcap_id
        }
        with scapy.utils.PcapReader(filename) as pcap:
            last = None
            outer_layers = set()
            max_len = 0
            for pkt in pcap:
                outer_layers.add(type(pkt.firstlayer()))
                if len(pkt) > max_len:
                    max_len = len(pkt)
                last = pkt
                if pcap_info["start"] is None:
                    pcap_info["start"] = pkt.time
                pcap_info["packets"] += 1
                pcap_info["bytes"] += len(pkt)
            for layer in outer_layers:
                if layer not in [scapy.layers.l2.Ether, scapy.layers.l2.Dot3]:
                    logger.warning(f"unsupported layer type: {layer} in {filename}")
            if max_len > 1518:
                logger.warning(f"jumbo frames (max {max_len} bytes) in {filename}")
            print()
            pcap_info["end"] = last.time
            pcap_info["duration"] = last.time - pcap_info["start"]
            replay_rate = 1
            replay_duration = pcap_info["duration"]
            if pcap_info["duration"] > self.max_duration:
                replay_rate = float(pcap_info["duration"] / self.max_duration)
                replay_duration = pcap_info["duration"] / replay_rate
            pcap_info["replay_rate"] = replay_rate
            pcap_info["replay_duration"] = replay_duration

        return pcap_info

    def add_pcap(self, filename):
        if filename in self.pcaps:
            raise Exception(f"pcap {filename} already added")
        self.pcaps[filename] = self.get_pcap_info(filename)

    def add_pcap_dir(self, pcap_dir):
        logger.debug(f"walking {pcap_dir}")
        if not os.path.isdir(pcap_dir):
            raise Exception(f"invalid directory: {pcap_dir}")
        for root, dirs, files in os.walk(pcap_dir):
            for f in files:
                # logger.debug(f"checking {root}/{f}")
                if f.endswith(".pcap") or f.endswith(".pcapng") or f.endswith(".cap"):
                    # logger.debug(f"adding {root}/{f}")
                    self.add_pcap(os.path.join(root, f))

    def build_schedule(self):
        pcaps_by_duration = sorted(
            self.pcaps.values(), key=lambda x: -x["replay_duration"]
        )
        total_duration = sum([x["replay_duration"] for x in pcaps_by_duration])
        min_threads = math.ceil(total_duration / self.max_duration)
        threads = []
        for i in range(min_threads):
            threads.append({"duration": 0, "pcaps": []})
        for pcap in pcaps_by_duration:
            for t in threads:
                if pcap["replay_duration"] + t["duration"] < self.max_duration:
                    t["pcaps"].append(pcap)
                    t["duration"] += pcap["replay_duration"]
                    break
            else:
                threads.append({"duration": pcap["replay_duration"], "pcaps": [pcap]})
        self.threads = threads

    def get_schedule(self):
        if self.threads is None:
            self.build_schedule()
        return self.threads

    def replay(self):
        schedule = self.get_schedule()
        processes = []
        for thread in schedule:
            # start a thread
            p = Process(target=self.replay_task, args=(thread["pcaps"],))
            processes.append(p)
            p.start()
        # wait for processes
        for process in processes:
            # fixme: might want to look for ones that are done first?
            process.join()

    def get_player_kwargs(self):
        return {}

    def replay_task(self, pcaps):
        logger.info("replay task")
        for pcap in pcaps:
            logger.info(f"replaying {pcap['filename']} at {pcap['replay_rate']}")
            player = self.PCAPPlayer(
                filename=pcap["filename"],
                speed=pcap["replay_rate"],
                pcap_id=pcap["id"],
                insert_log=self.insert_log,
                **self.get_player_kwargs(),
            )
            player.replay_pcap()


if __name__ == "__main__":
    pcap_dir = os.path.join(os.environ["HOME"], "pcap")
    sched = PCAPScheduler()

    sched.add_pcap_dir(pcap_dir)

    queue = sched.get_schedule()
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(queue)
    print(len(queue))
