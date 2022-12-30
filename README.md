# prometheus-tor_exporter
Prometheus exporter for the TOR daemon.

![prometheus-tor-exporter](https://user-images.githubusercontent.com/3966931/27349994-5cec464c-55f9-11e7-805a-2aea50413f2a.png)

_(the JSON descriptor file for this dashboard can be found [here](https://gist.github.com/atx/f4d12616eaac919b6764109ffd470c99))_ 


## Installation

Get the latest [release](https://github.com/atx/prometheus-tor_exporter/releases/latest/) and install using dpkg.

```
wget 'https://github.com/atx/prometheus-tor_exporter/releases/download/v0.3/prometheus-tor-exporter_0.3_all.deb'
dpkg -i prometheus-tor-exporter_0.3_all.deb
apt install -f
```

You can also build from source.

```
apt install git debhelper devscripts
git clone https://github.com/atx/prometheus-tor_exporter
cd prometheus-tor_exporter
debuild --no-tgz-check -uc -us
dpkg -i ../prometheus-tor-exporter_0.3_all.deb
```

Afterwards, you need to enable the installed systemd service.

```
systemctl enable --now prometheus-tor-exporter
```

## Configuration

prometheus-tor_exporter is configured using the `/etc/default/prometheus-tor-exporter`

```
# Additional parameters for prometheus-tor-exporter
ARGS="-p 8800"
```

The parameters can be listed py running `prometheus-tor-exporter.py -h`

```
usage: prometheus-tor-exporter.py [-h] [-m {tcp,unix}] [-a ADDRESS]
                                  [-c CONTROL_PORT] [-s CONTROL_SOCKET]
                                  [-p LISTEN_PORT] [-b BIND_ADDR]

optional arguments:
  -h, --help            show this help message and exit
  -m {tcp,unix}, --mode {tcp,unix}
                        Tor socker control mode (tcp or unix, default tcp)
  -a ADDRESS, --address ADDRESS
                        Tor control IP address
  -c CONTROL_PORT, --control-port CONTROL_PORT
                        Tor control port
  -s CONTROL_SOCKET, --control-socket CONTROL_SOCKET
                        Tor control socket
  -p LISTEN_PORT, --listen-port LISTEN_PORT
                        Listen on this port
  -b BIND_ADDR, --bind-addr BIND_ADDR
                        Bind this address
```

The password (if any) used to authenticate to the Tor control socket is read
from the environment variable `PROM_TOR_EXPORTER`.

## Exported metrics

  Name              |  Description
--------------------|-----------------------
tor_written_bytes   | Running total of written bytes
tor_read_bytes      | Running total of read bytes
tor_version{version="..."} | Tor daemon version as a tag
tor_version_status={version_status="..."} | Tor daemon version status as a tag
tor_network_liveness | Network liveness (1.0 or 0.0)
tor_reachable{port="OR\|DIR"} | Reachability of the OR/DIR ports (1.0 or 0.0)
tor_circuit_established | Indicates whether the daemon is capable of establishing circuits (1.0 or 0.0)
tor_dormant | Indicates whether tor is currently active (1.0 or 0.0) (note that 1.0 means "dormant", see the specs for details)
tor_effective_rate | Shows the effective rate of the relay
tor_effective_burst_rate | Shows the effective burst rate of the relay
tor_fingerprint{fingerprint="..."} | Node fingerprint as a tag
tor_nickname{nickname="..."} | Node nickname as a tag
tor_flags{flag="Authority\|BadExit\|Exit\|Fast\|<br/>Guard\|HSDir\|NoEdConsensus\|Stable\|<br/>Running\|Valid\|V2Dir"} | Indicates whether the node has a certain flag (1.0 or 0.0)
tor_bridge_clients_seen{country="..."} | Tor bridge clients per country. Reset every 24 hours and only increased by multiples of 8
tor_accounting_read_bytes | Amount of bytes read in the current accounting period
tor_accounting_left_read_bytes | Amount of read bytes left in the current accounting period
tor_accounting_read_limit_bytes | Read byte limit in the current accounting period
tor_accounting_write_bytes | Amount of bytes written in the current accounting period
tor_accounting_left_write_bytes | Amount of write bytes left in the current accounting period
tor_accounting_write_limit_bytes | Write byte limit in the current accounting period
tor_uptime | Uptime of the tor process (in seconds)


A more in-depth explanation of the various variables can be found in the [control port manual](https://gitweb.torproject.org/torspec.git/tree/control-spec.txt)
