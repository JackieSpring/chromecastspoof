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

import pytest
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP

from cspoof import sender
from cspoof.chromecast import Chromecast


def test_prefixes_match_original_order():
    assert sender.PREFIXES == [
        "_233637DE", "_096084372", "_5FD0CDC9", "_70CF0F1E",
        "_CC1AD845", "_9AC194DC", "",
    ]


class TestBuildPackets:
    def test_one_packet_per_device_and_prefix(self):
        devices = [Chromecast("A", "1.1.1.1"), Chromecast("B", "2.2.2.2", True)]
        assert len(sender.build_packets(devices)) == 2 * len(sender.PREFIXES)

    def test_no_devices_no_packets(self):
        assert sender.build_packets([]) == []

    def test_ip_and_udp_headers(self):
        (first, *_) = sender.build_packets([Chromecast("A", "1.1.1.1")])
        parsed = IP(bytes(first))
        assert parsed.dst == "224.0.0.251"
        assert parsed.ttl == 255
        assert parsed[UDP].sport == 5353
        assert parsed[UDP].dport == 5353

    def test_order_is_device_major_then_prefix(self):
        a, b = Chromecast("A", "1.1.1.1"), Chromecast("B", "2.2.2.2")
        packets = sender.build_packets([a, b])
        n = len(sender.PREFIXES)
        for i, packet in enumerate(packets):
            dev = a if i < n else b
            expected = bytes(dev.dns_packet(sender.PREFIXES[i % n]))
            assert bytes(IP(bytes(packet))[UDP].payload) == expected

    def test_payload_is_dns_response(self):
        (first, *_) = sender.build_packets([Chromecast("A", "1.1.1.1")])
        dns = IP(bytes(first))[DNS]
        assert dns.qr == 1 and dns.ancount == 1 and dns.arcount == 3


class TestSendAll:
    @pytest.fixture
    def calls(self, monkeypatch):
        calls = []

        def fake_send(x, **kwargs):
            # scapy >= 2.8 rejects iface= with anything but a single packet
            if isinstance(x, list):
                raise AttributeError("Cannot use iface= with this packet type.")
            calls.append((x, kwargs))

        monkeypatch.setattr(sender, "send", fake_send)
        return calls

    def test_requires_root(self, monkeypatch, calls):
        monkeypatch.setattr(sender.os, "geteuid", lambda: 501)
        with pytest.raises(PermissionError, match="sudo"):
            sender.send_all(["pkt"])
        assert calls == []

    def test_sends_each_packet_on_its_own(self, monkeypatch, calls):
        monkeypatch.setattr(sender.os, "geteuid", lambda: 0)
        sender.send_all(["p1", "p2"], iface="en0")
        assert calls == [
            ("p1", {"iface": "en0", "verbose": False}),
            ("p2", {"iface": "en0", "verbose": False}),
        ]

    def test_iface_defaults_to_none(self, monkeypatch, calls):
        monkeypatch.setattr(sender.os, "geteuid", lambda: 0)
        sender.send_all(["p"])
        assert calls[0][1]["iface"] is None
