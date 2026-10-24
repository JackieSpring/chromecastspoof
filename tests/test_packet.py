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

import hashlib
import socket
import struct

import pytest
from scapy.layers.dns import DNS

from cspoof.chromecast import Chromecast
from cspoof.sender import PREFIXES


def _octets(labels):
    return b"".join(bytes([len(l)]) + l.encode("utf-8") for l in labels) + b"\x00"


def reference_packet(name, ip, ultra, prefix):
    """Straight port of Chromecast.GetBroadcastPacket from the C# original."""
    digest = hashlib.md5(name.encode("ascii", "replace")).hexdigest()
    hostname = "Chromecast-" + ("Ultra-" if ultra else "") + digest
    service = ["_googlecast", "_tcp", "local"]

    out = struct.pack(">6H", 0, 0x8400, 0, 1, 0, 3)

    # Answer: PTR
    out += _octets(([prefix, "_sub"] if prefix else []) + service)
    ptr = _octets([hostname] + service)
    out += struct.pack(">HHIH", 12, 1, 120, len(ptr)) + ptr

    # Additional: TXT
    txt = b"".join(
        bytes([len(s.encode("utf-8"))]) + s.encode("utf-8")
        for s in [
            "id=" + digest, "cd=", "rm=", "ve=05", "md=Chromecast Ultra",
            "ic=/setup/icon.png", "fn=" + name, "ca=4101", "st=0", "bs=",
            "nf=1", "rs=",
        ]
    )
    out += _octets([hostname] + service)
    out += struct.pack(">HHIH", 16, 0x8001, 4500, len(txt)) + txt

    # Additional: SRV
    srv = struct.pack(">HHH", 0, 0, 8009) + _octets([hostname, "local"])
    out += _octets([hostname] + service)
    out += struct.pack(">HHIH", 33, 0x8001, 120, len(srv)) + srv

    # Additional: A
    out += _octets([hostname, "local"])
    out += struct.pack(">HHIH", 1, 0x8001, 120, 4) + socket.inet_aton(ip)
    return out


class TestIdentity:
    def test_hash_is_md5_of_name(self):
        c = Chromecast("Salotto", "1.2.3.4")
        assert c.id_hash == hashlib.md5(b"Salotto").hexdigest()

    def test_hash_replaces_non_ascii_like_dotnet(self):
        c = Chromecast("Caffè", "1.2.3.4")
        assert c.id_hash == hashlib.md5(b"Caff?").hexdigest()

    def test_hostname_regular(self):
        c = Chromecast("Salotto", "1.2.3.4")
        assert c.hostname == "Chromecast-" + c.id_hash

    def test_hostname_ultra(self):
        c = Chromecast("Salotto", "1.2.3.4", ultra=True)
        assert c.hostname == "Chromecast-Ultra-" + c.id_hash

    def test_ultra_defaults_to_false(self):
        assert Chromecast("Salotto", "1.2.3.4").ultra is False


class TestValidation:
    def test_empty_name_rejected(self):
        with pytest.raises(ValueError):
            Chromecast("", "1.2.3.4")

    @pytest.mark.parametrize("ip", ["", "abc", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.-4"])
    def test_invalid_ip_rejected(self, ip):
        with pytest.raises(ValueError):
            Chromecast("Salotto", ip)

    def test_name_too_long_for_txt_string_rejected(self):
        with pytest.raises(ValueError):
            Chromecast("a" * 253, "1.2.3.4")  # "fn=" + 253 > 255 bytes

    def test_name_at_txt_limit_accepted(self):
        Chromecast("a" * 252, "1.2.3.4")

    def test_utf8_name_length_counted_in_bytes(self):
        with pytest.raises(ValueError):
            Chromecast("è" * 127, "1.2.3.4")  # 254 bytes + "fn="


class TestDnsPacket:
    @pytest.mark.parametrize("ultra", [False, True])
    @pytest.mark.parametrize("prefix", PREFIXES)
    def test_matches_original_bytes(self, prefix, ultra):
        c = Chromecast("Salotto", "93.184.216.34", ultra)
        expected = reference_packet("Salotto", "93.184.216.34", ultra, prefix)
        assert bytes(c.dns_packet(prefix)) == expected

    def test_prefix_defaults_to_empty(self):
        c = Chromecast("Salotto", "1.2.3.4")
        assert bytes(c.dns_packet()) == bytes(c.dns_packet(""))

    def test_utf8_name_in_txt(self):
        c = Chromecast("Caffè", "1.2.3.4")
        assert bytes(c.dns_packet("")) == reference_packet("Caffè", "1.2.3.4", False, "")

    def test_header(self):
        pkt = DNS(bytes(Chromecast("Salotto", "1.2.3.4").dns_packet("")))
        assert pkt.id == 0
        assert pkt.qr == 1 and pkt.aa == 1 and pkt.opcode == 0 and pkt.rcode == 0
        assert (pkt.qdcount, pkt.ancount, pkt.nscount, pkt.arcount) == (0, 1, 0, 3)

    def test_record_counts_on_the_wire(self):
        # scapy >= 2.8 computes the counts from the record lists: chaining the
        # additional records with "/" used to yield arcount=1.
        raw = bytes(Chromecast("Salotto", "1.2.3.4").dns_packet(""))
        assert struct.unpack(">6H", raw[:12]) == (0, 0x8400, 0, 1, 0, 3)

    def test_parsed_records(self):
        c = Chromecast("Salotto", "93.184.216.34", ultra=True)
        pkt = DNS(bytes(c.dns_packet("_CC1AD845")))

        assert len(pkt.an) == 1 and len(pkt.ar) == 3
        ptr = pkt.an[0]
        assert ptr.type == 12 and ptr.cacheflush == 0 and ptr.rclass == 1 and ptr.ttl == 120
        assert ptr.rrname == b"_CC1AD845._sub._googlecast._tcp.local."
        assert ptr.rdata == c.hostname.encode() + b"._googlecast._tcp.local."

        txt, srv, a = pkt.ar[0], pkt.ar[1], pkt.ar[2]
        owner = c.hostname.encode() + b"._googlecast._tcp.local."

        assert txt.type == 16 and txt.cacheflush == 1 and txt.rclass == 1 and txt.ttl == 4500
        assert txt.rrname == owner
        assert txt.rdata == [
            b"id=" + c.id_hash.encode(), b"cd=", b"rm=", b"ve=05",
            b"md=Chromecast Ultra", b"ic=/setup/icon.png", b"fn=Salotto",
            b"ca=4101", b"st=0", b"bs=", b"nf=1", b"rs=",
        ]

        assert srv.type == 33 and srv.cacheflush == 1 and srv.rclass == 1 and srv.ttl == 120
        assert srv.rrname == owner
        assert (srv.priority, srv.weight, srv.port) == (0, 0, 8009)
        assert srv.target == c.hostname.encode() + b".local."

        assert a.type == 1 and a.cacheflush == 1 and a.rclass == 1 and a.ttl == 120
        assert a.rrname == c.hostname.encode() + b".local."
        assert a.rdata == "93.184.216.34"

    def test_md_is_always_chromecast_ultra(self):
        # Quirk kept from the original: md= does not depend on the Ultra flag.
        pkt = DNS(bytes(Chromecast("Salotto", "1.2.3.4", ultra=False).dns_packet("")))
        assert b"md=Chromecast Ultra" in pkt.ar[0].rdata
