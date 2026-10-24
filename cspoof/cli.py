# Copyright 2015 Nick Niemi
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Modified: ported from C# to Python 3 / scapy.

import argparse
import sys
import time

from . import sender
from .chromecast import Chromecast


def parse_device(value):
    """Parse NAME=IP[,ultra] into a Chromecast."""
    ultra = False
    head, comma, flag = value.rpartition(",")
    if comma and flag.strip().lower() == "ultra":
        ultra = True
        value = head
    name, equals, ip = value.rpartition("=")
    if not equals:
        raise argparse.ArgumentTypeError(f"expected NAME=IP[,ultra], got {value!r}")
    try:
        return Chromecast(name, ip, ultra)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def positive_float(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number: {value!r}") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cspoof",
        description="Send fake mDNS packets so a Chromecast on another network shows up locally.",
    )
    parser.add_argument("-d", "--device", dest="devices", action="append", required=True,
                        type=parse_device, metavar="NAME=IP[,ultra]",
                        help="device to announce; repeat for multiple devices")
    parser.add_argument("--loop", action="store_true",
                        help="keep sending until interrupted (Ctrl+C)")
    parser.add_argument("--interval", type=positive_float, default=2.5, metavar="SECONDS",
                        help="seconds between rounds with --loop (default: 2.5)")
    parser.add_argument("--iface", help="network interface to send from")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    packets = sender.build_packets(args.devices)
    try:
        while True:
            sender.send_all(packets, iface=args.iface)
            print(f"Sent {len(packets)} packets for {len(args.devices)} device(s)")
            if not args.loop:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0
    except OSError as e:
        print(f"cspoof: {e}", file=sys.stderr)
        return 1
