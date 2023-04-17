#!/usr/bin/env python3

import argparse
import logging
from multiprocessing import Process

from pcap_schedule import PCAPScheduler
from replay_vxlan import PCAPPlayerVXLAN

logging.basicConfig(
    format="%(asctime)s [%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
)
logger = logging.getLogger("root")
logger.setLevel(logging.DEBUG)
# logger.addHandler(logging.StreamHandler())


class PCAPSchedVXLAN(PCAPScheduler):
    def __init__(self, target_ip, *args, **kw):
        self.target_ip = target_ip

        super().__init__(*args, **kw)

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

    def replay_task(self, pcaps):
        logger.info("replay task")
        for pcap in pcaps:
            logger.info(f"replaying {pcap['filename']} at {pcap['replay_rate']}")
            player = PCAPPlayerVXLAN(
                filename=pcap["filename"],
                speed=pcap["replay_rate"],
                target_ip=self.target_ip,
            )
            player.replay_pcap()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("pcap_dir")
    parser.add_argument("-t", "--target-ip", type=str)
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=4 * 60 * 60,
        help="attempt to replay all PCAPs in duration seconds",
    )

    args = parser.parse_args()

    # raise Exception("stop")
    logger.info("get scheduler")
    sched = PCAPSchedVXLAN(
        target_ip=args.target_ip,
        max_duration=args.duration,
    )
    logger.info("parsing pcaps")
    sched.add_pcap_dir(args.pcap_dir)
    logger.info("starting replay")
    sched.replay()
