#!/usr/bin/env python3

import argparse
import logging

from pcap_schedule import PCAPScheduler
from replay import PCAPPlayerPacket, PCAPPlayerVXLAN, PCAPPlayerGENEVE

logging.basicConfig(
    format="%(asctime)s [%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
)
logger = logging.getLogger("root")
logger.setLevel(logging.DEBUG)
# logger.addHandler(logging.StreamHandler())


class PCAPSchedUDPBase(PCAPScheduler):
    PCAPPlayer = None

    def __init__(self, target_ip, *args, **kw):
        self.target_ip = target_ip

        super().__init__(*args, **kw)

    def get_player_kwargs(self):
        args = super().get_player_kwargs()
        args["target_ip"] = self.target_ip
        return args


class PCAPSchedVXLAN(PCAPSchedUDPBase):
    PCAPPlayer = PCAPPlayerVXLAN


class PCAPSchedGENEVE(PCAPSchedUDPBase):
    PCAPPlayer = PCAPPlayerGENEVE


class PCAPSchedPacket(PCAPScheduler):
    PCAPPlayer = PCAPPlayerPacket

    def __init__(self, interface, *args, **kw):
        self.interface = interface

        super().__init__(*args, **kw)

    def get_player_kwargs(self):
        args = super().get_player_kwargs()
        args["interface"] = self.interface
        return args


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-l", "--insert-log", action="store_true", default=False)

    parser.add_argument(
        "-N",
        "--dry-run",
        action="store_true",
        default=False,
        help="Don't actually send packets, just parse pcaps",
    )

    parser.add_argument("pcap_dir")
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=4 * 60 * 60,
        help="attempt to replay all PCAPs in duration seconds",
    )

    subparsers = parser.add_subparsers(dest="output_type")
    subparsers.required = True

    parser_vxlan = subparsers.add_parser("vxlan")
    parser_vxlan.add_argument("-t", "--target-ip", type=str)

    parser_vxlan = subparsers.add_parser("geneve")
    parser_vxlan.add_argument("-t", "--target-ip", type=str)

    parser_packet = subparsers.add_parser("packet")
    parser_packet.add_argument("-i", "--interface", type=str)

    args = parser.parse_args()
    # raise Exception("stop")
    logger.info("get scheduler")
    if args.output_type == "vxlan":
        sched = PCAPSchedVXLAN(
            target_ip=args.target_ip,
            max_duration=args.duration,
            insert_log=args.insert_log,
        )
    elif args.output_type == "geneve":
        sched = PCAPSchedGENEVE(
            target_ip=args.target_ip,
            max_duration=args.duration,
            insert_log=args.insert_log,
        )
    elif args.output_type == "packet":
        sched = PCAPSchedPacket(
            interface=args.interface,
            max_duration=args.duration,
            insert_log=args.insert_log,
        )
    logger.info("parsing pcaps")
    sched.add_pcap_dir(args.pcap_dir)

    if args.dry_run:
        logger.info("dry run: skipping replay")
        exit(0)

    logger.info("starting replay")
    sched.replay()
