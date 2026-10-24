# Chromecast Spoof (CSpoof)
A Python 3 command-line tool that sends fake multicast DNS packets (built with [scapy](https://scapy.net)), allowing you to cast from a mobile device to a Chromecast on a different network.

Originally designed to play Cardcast (http://www.cardcastgame.com) remotely.

Originally created in C# by Ephemerality <ephemeral.vilification@gmail.com>

## Requirements
* Mobile device capable of casting to a Chromecast
* A computer on the same network as your mobile device, with Python 3 and root privileges (scapy sends raw packets)
* `pip install -r requirements.txt` (scapy 2.8 or later)
* `sudo` may pick a different Python than your shell (e.g. a Homebrew alias): install scapy for that interpreter, or run `sudo $(which python3) -m cspoof ...`

## Instructions
* Forward ports 8008-8009, TCP and UDP, to your Chromecast
* Run the tool on a computer on the same network as your mobile device, passing the name you want to display (it does not need to match your Chromecast) and the public IP address of your Chromecast:

```
sudo python3 -m cspoof -d "Living room=203.0.113.10"
```

* Repeat `-d` to announce several devices, and add `,ultra` to announce a Chromecast Ultra:

```
sudo python3 -m cspoof -d "Living room=203.0.113.10" -d "Kitchen=203.0.113.20,ultra"
```

* Use `--loop` to keep sending until Ctrl+C (every 2.5 seconds, change it with `--interval`)
* Use `--iface en0` to choose the network interface to send from
* You should now see the fake Chromecast show up on the mobile device
* If the ports are properly forwarded and the correct IP was entered, you should be able to cast to it
* If you have VMWare/VirtualBox installed, you may have to pick the right interface with `--iface`

## Tests
```
python3 -m pytest
```

## License
Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
This is a port of the original C# ChromecastSpoof by Nick Niemi.
