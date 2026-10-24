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
import ipaddress
from dataclasses import dataclass

from scapy.layers.dns import DNS, DNSRR, DNSRRSRV

SERVICE = "_googlecast._tcp.local"
CAST_PORT = 8009
MAX_TXT_STRING = 255


@dataclass(frozen=True)
class Chromecast:
    name: str
    ip: str
    ultra: bool = False

    def __post_init__(self):
        if not self.name:
            raise ValueError("Name cannot be blank.")
        try:
            ipaddress.IPv4Address(self.ip)
        except ValueError:
            raise ValueError(f"Invalid IP: {self.ip!r}") from None
        if len(self._fn.encode("utf-8")) > MAX_TXT_STRING:
            raise ValueError("Name is too long.")

    @property
    def id_hash(self):
        # ASCII with '?' substitution, as Encoding.ASCII does in .NET
        return hashlib.md5(self.name.encode("ascii", "replace")).hexdigest()

    @property
    def hostname(self):
        return "Chromecast-" + ("Ultra-" if self.ultra else "") + self.id_hash

    @property
    def _fn(self):
        return "fn=" + self.name

    def dns_packet(self, prefix=""):
        """mDNS response announcing this device under the given service prefix."""
        owner = f"{self.hostname}.{SERVICE}"
        target = f"{self.hostname}.local"
        subtype = f"{prefix}._sub.{SERVICE}" if prefix else SERVICE

        txt = [
            "id=" + self.id_hash,
            "cd=",
            "rm=",
            "ve=05",
            "md=Chromecast Ultra",
            "ic=/setup/icon.png",
            self._fn,
            "ca=4101",
            "st=0",
            "bs=",
            "nf=1",
            "rs=",
        ]

        answer = DNSRR(rrname=subtype, type="PTR", rclass=1, ttl=120, rdata=owner)
        additional = [
            DNSRR(rrname=owner, type="TXT", cacheflush=1, rclass=1, ttl=4500,
                  rdata=[s.encode("utf-8") for s in txt]),
            DNSRRSRV(rrname=owner, cacheflush=1, rclass=1, ttl=120,
                     priority=0, weight=0, port=CAST_PORT, target=target),
            DNSRR(rrname=target, type="A", cacheflush=1, rclass=1, ttl=120,
                  rdata=self.ip),
        ]
        return DNS(id=0, qr=1, aa=1, rd=0, qd=[], an=[answer], ar=additional)
