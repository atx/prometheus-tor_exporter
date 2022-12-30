#! /usr/bin/env python3
# Source: https://github.com/atx/prometheus-tor_exporter/blob/master/prometheus-tor-exporter.py

import argparse
import stem
import stem.control
import time
import re
import sys
import os
from retrying import retry
import prometheus_client as prom
from prometheus_client.core import GaugeMetricFamily, REGISTRY

password_env_var = "PROM_TOR_EXPORTER_PASSWORD"

class StemCollector:

    def __init__(self, tor):
        self.tor = tor

        self.password = ""
        try:
            self.password = os.environ[password_env_var]
        except:
            pass

        self.authenticate()
        self.reconnect()

    @retry(wait_random_min=1000, wait_random_max=2000, stop_max_attempt_number=5)
    def authenticate(self):
        try:
            self.tor.authenticate(password=self.password)
        except stem.connection.IncorrectPassword:
            print("Failed password authentication to the Tor control socket.\n"
                    "The password is read from the environment variable "
                    "{}.".format(password_env_var),
                    file = sys.stderr)
            sys.exit(1)

    @retry(wait_random_min=1000, wait_random_max=2000, stop_max_attempt_number=5)
    def reconnect(self):
        try:
            self.tor.reconnect(password=self.password)
        except stem.connection.IncorrectPassword:
            print("Failed password authentication to the Tor control socket.\n"
                    "The password is read from the environment variable "
                    "{}.".format(password_env_var),
                    file = sys.stderr)
            sys.exit(1)

    def collect(self):
        self.reconnect()

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
                    "Tor version status {new, old, unrecommended, "
                    "recommended, new in series, obsolete, unknown} as a "
                    "label",
                    labels=["version_status"])
        version_status.add_metric(
                    [self.tor.get_info("status/version/current")], 1)
        yield version_status

        yield GaugeMetricFamily(
                "tor_network_liveness",
                "Indicates whether tor believes that the network is currently "
                "reachable",
                value=int(self.tor.get_info("network-liveness") == "up"))

        reachable = GaugeMetricFamily(
                "tor_reachable",
                "Indicates whether tor OR/Dir port is reachable",
                labels=["port"])
        for entry in self.tor.get_info("status/reachability-succeeded").split():
            k, v = entry.split("=")
            reachable.add_metric([k], int(v))
        yield reachable

        yield GaugeMetricFamily(
                "tor_circuit_established",
                "Indicates whether Tor is capable of establishing circuits",
                value=int(self.tor.get_info("status/circuit-established")))

        # For some reason, 0 actually means that Tor is active.
        # Keep it that way.
        yield GaugeMetricFamily(
                "tor_dormant",
                "Indicates whether Tor is currently active and building "
                "circuits (note that 0 corresponds to Tor being active)",
                value=int(self.tor.get_info("dormant")))

        effective_rate = self.tor.get_effective_rate(None)
        effective_burst_rate = self.tor.get_effective_rate(None, burst=True)
        if effective_rate is not None and effective_burst_rate is not None:
            yield GaugeMetricFamily("tor_effective_rate",
                                    "Tor effective bandwidth rate",
                                    value=int(effective_rate))
            yield GaugeMetricFamily("tor_effective_burst_rate",
                                    "Tor effective burst bandwidth rate",
                                    value=int(effective_burst_rate))

        try:
            fingerprint_value = self.tor.get_info("fingerprint")
            fingerprint = GaugeMetricFamily(
                    "tor_fingerprint",
                    "Tor server fingerprint as a label",
                    labels=["fingerprint"])
            fingerprint.add_metric([fingerprint_value], 1)
            yield fingerprint
        except (stem.ProtocolError, stem.OperationFailed):
            # happens when not running in server mode
            pass

        nickname = GaugeMetricFamily("tor_nickname",
                                     "Tor nickname as a label",
                                     labels=["nickname"])
        nickname.add_metric([self.tor.get_conf("Nickname", "Unnamed")], 1)
        yield nickname

        # Connection counting
        # This won't work/will return wrong results if we are not running on
        # the same box as the Tor daemon is.
        # DisableDebuggerAttachment has to be set to 0
        # TODO: Count individual OUT/DIR/Control connections, see arm sources
        # for reference
        try:
            tor_pid = self.tor.get_pid()
            connections = stem.util.connection.get_connections(
                                                process_pid=tor_pid)
            yield GaugeMetricFamily(
                    "tor_connection_count",
                    "Amount of connections the Tor daemon has open",
                    value=len(connections))
        except (OSError, IOError):
            # This happens if the PID does not exists (on another machine).
            pass

        try:
            has_flags = self.tor.get_network_status().flags
        except stem.DescriptorUnavailable:
            # The tor daemon fails with this for a few minutes after startup
            # (before figuring out its own flags?)
            has_flags = []
        except stem.ControllerError:
            # Happens when the daemon is not running in server mode
            has_flags = []
        flags = GaugeMetricFamily("tor_flags", "Has a Tor flag", labels=["flag"])
        for flag in ["Authority", "BadExit", "Exit", "Fast", "Guard", "HSDir",
                     "NoEdConsensus", "Stable", "Running", "Valid", "V2Dir"]:
            flags.add_metric([flag], int(flag in has_flags))
        yield flags

        regex = re.compile(".*CountrySummary=([a-z0-9=,]+)")
        countrysum = regex.match(self.tor.get_info("status/clients-seen"))
        if countrysum != None:
            countrysum = countrysum.group(1).split(",")
            bridge_clients_seen = GaugeMetricFamily(
                        "tor_bridge_clients_seen",
                        "Tor bridge clients per country. Reset every 24 hours "
                        "and only increased by multiples of 8.",
                        labels = ["country"])
            countrycode = [c[:2] for c in countrysum]
            countryclients = [int(c[3:]) for c in countrysum]
            for i in range(len(countrycode)):
                bridge_clients_seen.add_metric(
                        [countrycode[i]], countryclients[i])
            yield bridge_clients_seen

        try:
            accs = self.tor.get_accounting_stats()
            yield GaugeMetricFamily("tor_accounting_read_bytes",
                                    "Tor accounting read bytes",
                                    accs.read_bytes)
            yield GaugeMetricFamily("tor_accounting_left_read_bytes",
                                    "Tor accounting read bytes left",
                                    accs.read_bytes_left)
            yield GaugeMetricFamily("tor_accounting_read_limit_bytes",
                                    "Tor accounting read bytes limit",
                                    accs.read_limit)
            yield GaugeMetricFamily("tor_accounting_write_bytes",
                                    "Tor accounting write bytes",
                                    accs.written_bytes)
            yield GaugeMetricFamily("tor_accounting_left_write_bytes",
                                    "Tor accounting write bytes left",
                                    accs.write_bytes_left)
            yield GaugeMetricFamily("tor_accounting_write_limit_bytes",
                                    "Tor accounting write bytes limit",
                                    accs.write_limit)
        except stem.ControllerError:
            # happens when accounting isn't enabled
            pass

        yield GaugeMetricFamily("tor_uptime",
                                "Tor daemon uptime in seconds",
                                value=int(self.tor.get_info("uptime")))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-m", "--mode",
        help="Tor socker control mode (tcp or unix, default tcp)",
        default="tcp",
        choices=['tcp', 'unix']
    )
    parser.add_argument(
        "-a", "--address",
        help="Tor control IP address",
        default="127.0.0.1"
    )
    parser.add_argument(
        "-c", "--control-port",
        help="Tor control port",
        type=int,
        default=9051
    )
    parser.add_argument(
        "-s", "--control-socket",
        help="Tor control socket",
        default="/var/run/tor/control"
    )
    parser.add_argument(
        "-p", "--listen-port",
        help="Listen on this port",
        type=int,
        default=9099
    )
    parser.add_argument(
        "-b", "--bind-addr",
        help="Bind this address",
        default="localhost"
    )
    args = parser.parse_args()

    if args.mode == 'unix':
        torctl = stem.control.Controller.from_socket_file(args.control_socket)
    else:
        torctl = stem.control.Controller.from_port(args.address,
                                                   port=args.control_port)
    coll = StemCollector(torctl)
    REGISTRY.register(coll)

    print("Starting on %s:%s" % (args.bind_addr, args.listen_port))
    prom.start_http_server(args.listen_port, addr=args.bind_addr)

    # We can't exit as start_http_server starts a daemon thread which would get
    # killed.
    while True:
        time.sleep(1000)
