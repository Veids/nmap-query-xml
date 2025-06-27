import sys, argparse

from typing import Optional
from string import Template
from libnmap.parser import NmapParser, NmapReport, NmapParserException


class NmapQuery:
    conf: int
    service: str
    pattern: str
    state: str

    def __init__(
        self, pattern: str, conf: int = -1, service: str = "", state: str = "open"
    ):
        self.pattern = pattern
        self.conf = conf
        self.service = service
        self.state = state

    def _get_hostname(self, host):
        return host.address if not host.hostnames else host.hostnames[0]

    def _get_hostnames(self, host):
        return host.address if not host.hostnames else ", ".join(set(host.hostnames))

    def _parse_entity(self, host, service):
        tpl = Template(self.pattern)

        return tpl.safe_substitute(
            hostname=self._get_hostname(host),
            hostnames=host.address
            if not host.hostnames
            else ", ".join(set(host.hostnames)),
            ip=host.address,
            service=service.service,
            s="s" if service.tunnel == "ssl" else "",
            protocol=service.protocol,
            port=service.port,
            state=service.state,
        )

    def _service_matches(self, service) -> bool:
        if not self.service:
            return True
        allowed = set(self.service.split(","))
        return service.service in allowed

    def _get_confidence(self, service) -> int:
        try:
            return int(getattr(service, "_service", {}).get("conf", 0))
        except Exception:
            return 0

    def process(self, report: NmapReport):
        for host in report.hosts:
            for service in host.services:
                if (
                    (service.state == self.state or self.state == "all")
                    and self._service_matches(service)
                    and (self.conf == -1 or self._get_confidence(service) <= self.conf)
                ):
                    yield self._parse_entity(host, service)


def parse_args():
    greeter = """
     ▐ ▄ • ▌ ▄ ·.  ▄▄▄·  ▄▄▄·    .▄▄▄  ▄• ▄▌▄▄▄ .▄▄▄   ▄· ▄▌    ▐▄• ▄ • ▌ ▄ ·. ▄▄▌
    •█▌▐█·██ ▐███▪▐█ ▀█ ▐█ ▄█    ▐▀•▀█ █▪██▌▀▄.▀·▀▄ █·▐█▪██▌     █▌█▌▪·██ ▐███▪██•
    ▐█▐▐▌▐█ ▌▐▌▐█·▄█▀▀█  ██▀·    █▌·.█▌█▌▐█▌▐▀▀▪▄▐▀▀▄ ▐█▌▐█▪     ·██· ▐█ ▌▐▌▐█·██▪
    ██▐█▌██ ██▌▐█▌▐█ ▪▐▌▐█▪·•    ▐█▪▄█·▐█▄█▌▐█▄▄▌▐█•█▌ ▐█▀·.    ▪▐█·█▌██ ██▌▐█▌▐█▌▐▌
    ▀▀ █▪▀▀  █▪▀▀▀ ▀  ▀ .▀       ·▀▀█.  ▀▀▀  ▀▀▀ .▀  ▀  ▀ •     •▀▀ ▀▀▀▀  █▪▀▀▀.▀▀▀ """
    for c in "█▐▌▄▀":
        greeter = greeter.replace(c, "\u001b[32m" + c + "\u001b[0m")
    version = "0.0.3#beta"
    url = "https://github.com/honze-net/nmap-query-xml"

    parser = argparse.ArgumentParser(
        description="",
        epilog="Full documentation: %s\nThis software must not be used by military or secret service organisations."
        % url,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("xml", help="path to Nmap XML file")
    parser.add_argument(
        "--service",
        help="Nmap service name to filter for. Default: Empty",
        default="",
        dest="service",
    )
    parser.add_argument(
        "--pattern",
        help="Pattern for output. Default: %(default)s",
        default="$service$s://$hostname:$port",
        dest="pattern",
    )
    parser.add_argument(
        "--state",
        help='Select a port state. Use "all" for all. Default: %(default)s',
        default="open",
        dest="state",
    )
    parser.add_argument(
        "--conf", help="Select conf level", type=int, default=-1, dest="conf"
    )

    if (
        len(sys.argv) == 1
    ):  # If no arguments are specified, print greeter, help and exit.
        print(greeter)
        print(("version %s %s\n" % (version, url)).center(80))
        parser.print_help()
        sys.exit(0)

    return parser.parse_args()


def load_report(path: str) -> Optional[NmapReport]:
    try:
        return NmapParser.parse_fromfile(path, incomplete=False)
    except NmapParserException:
        try:
            return NmapParser.parse_fromfile(path, incomplete=True)
        except NmapParserException as exc:
            print("NmapParser failed: %s" % exc)
            return None
    except IOError:
        print("Error: File %s not found." % path)
        return None

def main():
    args = parse_args()
    report = load_report(args.xml)

    if report is None:
        return

    nq = NmapQuery(
        pattern=args.pattern, conf=args.conf, service=args.service, state=args.state
    )

    for line in nq.process(report):
        print(line)


if __name__ == "__main__":
    main()
