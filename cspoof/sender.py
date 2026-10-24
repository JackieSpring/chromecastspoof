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

import os

from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

# Cast receiver app subtypes announced under _googlecast._tcp ("" = plain service)
PREFIXES = ["_233637DE", "_096084372", "_5FD0CDC9", "_70CF0F1E", "_CC1AD845", "_9AC194DC", ""]


def build_packets(devices):
    """One mDNS packet per device and prefix, device-major."""
    return [
        IP(dst=MDNS_ADDR, ttl=255)
        / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
        / device.dns_packet(prefix)
        for device in devices
        for prefix in PREFIXES
    ]


def send_all(packets, iface=None):
    if os.geteuid() != 0:
        raise PermissionError("root privileges required to send raw packets, run with sudo")
    # scapy >= 2.8 accepts iface= only with a single packet, not a list
    for packet in packets:
        send(packet, iface=iface, verbose=False)
