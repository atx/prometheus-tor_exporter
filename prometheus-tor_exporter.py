#! /usr/bin/env python3

import argparse
import stem
import stem.control
import time
import prometheus_client as prom
from prometheus_client.core import GaugeMetricFamily, REGISTRY

class StemCollector:

    def __init__(self, tor):
        self.tor = tor
        self.tor.reconnect()

    def collect(self):
        self.tor.reconnect()
        yield GaugeMetricFamily(
                    "tor_written_bytes",
                    "Tor written data counter",
                    value=int(self.tor.get_info("traffic/written")))
        yield GaugeMetricFamily(
                    "tor_read_bytes",
                    "Tor received data counter",
                    value=int(self.tor.get_info("traffic/read")))

        version = GaugeMetricFamily("tor_version", "Tor version as a label",
                                    labels=["version"])
        version.add_metric([str(torctl.get_version())], 1)
        yield version
        version_status = GaugeMetricFamily(
                            "tor_version_status",
                            "Tor version status {new, old, unrecommended, recommended, new in series, obsolete, unknown} as a label",
                            labels=["version_status"])
        version_status.add_metric([self.tor.get_info("status/version/current")], 1)
        yield version_status
        yield GaugeMetricFamily("tor_network_liveness",
                                "Indicates whether tor believes that the network is currently reachable",
                                value=int(self.tor.get_info("network-liveness") == "up"))
        reachable = GaugeMetricFamily("tor_reachable",
                                      "Indicates whether our OR/Dir port is reachable",
                                      labels=["port"])
        for entry in self.tor.get_info("status/reachability-succeeded").split():
            k, v = entry.split("=")
            reachable.add_metric([k], int(v))
        yield reachable
        yield GaugeMetricFamily("tor_circuit_established",
                                "Indicates whether Tor is capable of establishing circuits",
                                value=int(self.tor.get_info("status/circuit-established")))
        # For some reason, 0 actually means that Tor is active, keep it that way
        yield GaugeMetricFamily("tor_dormant",
                                "Indicates whether Tor is currently active and building circuits (note that 0 corresponds to Tor being active)",
                                value=int(self.tor.get_info("dormant")))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a", "--address",
        help="Tor control IP address",
        default="127.0.0.1"
    )
    parser.add_argument(
        "-c", "--control-port",
        help="Tor control port",
        default=9051
    )
    parser.add_argument(
        "-p", "--listen-port",
        help="Listen on this port",
        default=9099
    )
    parser.add_argument(
        "-b", "--bind-addr",
        help="Bind this address",
        default="localhost"
    )
    args = parser.parse_args()

    torctl = stem.control.Controller.from_port(args.address,
                                               port=args.control_port)
    torctl.authenticate()

    coll = StemCollector(torctl)
    REGISTRY.register(coll)

    print("Starting on %s:%s" % (args.bind_addr, args.listen_port))
    prom.start_http_server(args.listen_port, addr=args.bind_addr)

    # We can't exit as start_http_server starts a daemon thread which would get
    # killed.
    while True:
        time.sleep(1000)
