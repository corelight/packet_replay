#!/usr/bin/env python3

import logging
import math
import os
import pickle
import pprint
from multiprocessing import Process

import scapy.utils

logger = logging.getLogger("pcap_schedule")

cachedir = ".packet_replay"


class PCAPFileInfo(object):
    def __init__(self, filename, pcap_id):
        basename = os.path.basename(filename)
        dirname = os.path.dirname(filename)

        self._filename = basename
        self._filepath = dirname
        self._filename_long = filename

        self._pcap_id = pcap_id

        current_cache_dir = os.path.join(dirname, cachedir)
        if not os.path.isdir(current_cache_dir):
            os.makedirs(current_cache_dir)

        self._filecache = os.path.join(current_cache_dir, f"{self._filename}.cache")
        self._filecache_loaded = False
        self._filecache_entries = {}

        self.load_pcap_cache()

    def load_pcap_cache(self):
        if os.path.isfile(self._filecache):
            s = os.stat(self._filecache)
            if s.st_mtime == self._filecache_loaded:
                return
            with open(self._filecache, "rb") as f:
                loaded_entries = pickle.load(f)
                self._filecache_entries.update(loaded_entries)
                self._filecache_loaded = s.st_mtime

    def save_pcap_cache(self):
        # FIXME: may be race conditions, but should hopefully stay consistent
        print(f"saving to {self._filecache} ({self._filename_long})")
        new_cache = f"{self._filecache}.new-{os.getpid()}"
        try:
            with open(new_cache, "wb") as f:
                pickle.dump(self._filecache_entries, f)
            os.rename(new_cache, self._filecache)
        finally:
            if os.path.isfile(new_cache):
                os.unlink(new_cache)

    def _get_pcap_info(self):
        logger.debug(f"get info for {self._filename_long}")
        pcap_info = {
            "filename": self._filename,
            "packets": 0,
            "bytes": 0,
            "start": None,
            "end": None,
            "duration": None,
        }
        warnings = []
        with scapy.utils.PcapReader(self._filename_long) as pcap:
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

            unsupported_layer_types = []
            for layer in outer_layers:
                if layer not in [scapy.layers.l2.Ether, scapy.layers.l2.Dot3]:
                    w = f"unsupported layer type: {layer} in {self._filename_long}"
                    logger.warning(w)
                    warnings.append(w)
                    unsupported_layer_types.append(str(layer))
            pcap_info["unsupported_layer_types"] = unsupported_layer_types

            if max_len > 1518:
                w = f"jumbo frames (max {max_len} bytes) in {self._filename_long}"
                logger.warning(w)
                warnings.append(w)
                pcap_info["jumbo"] = True
            pcap_info["max_len"] = max_len

            print()
            pcap_info["end"] = last.time
            pcap_info["duration"] = last.time - pcap_info["start"]

        return pcap_info

    def get_pcap_info_cached(self):
        s = os.stat(self._filename_long)

        valid_cache = False
        if self._filecache_loaded:
            valid_cache = True
            cached = self._filecache_entries.copy()
            cached_s = self._filecache_entries["stat"]

            for i in ["st_ctime", "st_mtime", "st_size"]:
                if getattr(s, i) != getattr(cached_s, i):
                    valid_cache = False
                    break

            if valid_cache:
                cached["filename"] = self._filename_long
                return cached

        pcap_info = self._get_pcap_info()
        pcap_info["stat"] = s

        self._filecache_entries.update(pcap_info)
        self.save_pcap_cache()

        return pcap_info

    def get_pcap_info(self, max_duration):
        pcap_info = self.get_pcap_info_cached()

        # Don't cache these
        replay_rate = 1
        replay_duration = pcap_info["duration"]
        if pcap_info["duration"] > max_duration:
            replay_rate = float(pcap_info["duration"] / max_duration)
            replay_duration = pcap_info["duration"] / replay_rate
        pcap_info["replay_rate"] = replay_rate
        pcap_info["replay_duration"] = replay_duration
        pcap_info["pcap_id"] = self._pcap_id

        return pcap_info


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

    def add_pcap(self, filename):
        if filename in self.pcaps:
            raise Exception(f"pcap {filename} already added")
        logger.info(f"adding {filename}")
        self.current_pcap_id += 1
        info = PCAPFileInfo(filename, self.current_pcap_id)
        self.pcaps[filename] = info.get_pcap_info(max_duration=self.max_duration)

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
                pcap_id=pcap["pcap_id"],
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
