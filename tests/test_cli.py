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

import pytest

from cspoof import cli, sender
from cspoof.chromecast import Chromecast


class TestParseDevice:
    def test_name_and_ip(self):
        assert cli.parse_device("Salotto=1.2.3.4") == Chromecast("Salotto", "1.2.3.4", False)

    def test_ultra_suffix(self):
        assert cli.parse_device("Cucina=5.6.7.8,ultra") == Chromecast("Cucina", "5.6.7.8", True)

    def test_name_may_contain_equals_and_commas(self):
        assert cli.parse_device("a=b, c=1.2.3.4") == Chromecast("a=b, c", "1.2.3.4", False)

    def test_name_may_contain_spaces(self):
        assert cli.parse_device("Sala TV=1.2.3.4").name == "Sala TV"

    @pytest.mark.parametrize("value", [
        "Salotto",             # no '='
        "=1.2.3.4",            # empty name
        "Salotto=",            # empty ip
        "Salotto=999.1.1.1",   # invalid ip
        "Salotto=1.2.3.4,foo", # unknown flag
        "",
    ])
    def test_invalid(self, value):
        with pytest.raises(argparse.ArgumentTypeError):
            cli.parse_device(value)


@pytest.fixture
def fake_send(monkeypatch):
    calls = []
    monkeypatch.setattr(sender, "send_all", lambda packets, iface=None: calls.append((packets, iface)))
    return calls


class TestMain:
    def test_single_shot(self, fake_send):
        assert cli.main(["-d", "A=1.1.1.1", "-d", "B=2.2.2.2,ultra"]) == 0
        assert len(fake_send) == 1
        packets, iface = fake_send[0]
        assert len(packets) == 2 * len(sender.PREFIXES)
        assert iface is None

    def test_iface_passed_through(self, fake_send):
        cli.main(["-d", "A=1.1.1.1", "--iface", "en0"])
        assert fake_send[0][1] == "en0"

    def test_device_is_required(self, fake_send, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.main([])
        assert exc.value.code == 2
        assert fake_send == []

    def test_invalid_device_exits_with_usage_error(self, fake_send):
        with pytest.raises(SystemExit) as exc:
            cli.main(["-d", "nonsense"])
        assert exc.value.code == 2
        assert fake_send == []

    def test_loop_repeats_until_ctrl_c(self, fake_send, monkeypatch):
        sleeps = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) == 3:
                raise KeyboardInterrupt

        monkeypatch.setattr(cli.time, "sleep", fake_sleep)
        assert cli.main(["-d", "A=1.1.1.1", "--loop"]) == 0
        assert len(fake_send) == 3
        assert sleeps == [2.5, 2.5, 2.5]

    def test_loop_custom_interval(self, fake_send, monkeypatch):
        sleeps = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            raise KeyboardInterrupt

        monkeypatch.setattr(cli.time, "sleep", fake_sleep)
        cli.main(["-d", "A=1.1.1.1", "--loop", "--interval", "10"])
        assert sleeps == [10.0]

    @pytest.mark.parametrize("value", ["0", "-1", "abc"])
    def test_invalid_interval(self, fake_send, value):
        with pytest.raises(SystemExit) as exc:
            cli.main(["-d", "A=1.1.1.1", "--loop", "--interval", value])
        assert exc.value.code == 2

    def test_no_sleep_without_loop(self, fake_send, monkeypatch):
        monkeypatch.setattr(cli.time, "sleep", lambda s: pytest.fail("must not sleep"))
        cli.main(["-d", "A=1.1.1.1"])

    def test_permission_error_returns_1(self, monkeypatch, capsys):
        def deny(packets, iface=None):
            raise PermissionError("root privileges required, run with sudo")

        monkeypatch.setattr(sender, "send_all", deny)
        assert cli.main(["-d", "A=1.1.1.1"]) == 1
        assert "sudo" in capsys.readouterr().err
