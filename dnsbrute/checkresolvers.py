from __future__ import print_function
import sys
import argparse
import logging
import random
import time
import requests
import pkg_resources
import progressbar
import gevent
import gevent.pool
from dns.resolver import Resolver, Answer
from dns.exception import DNSException


LOG = logging.getLogger(__name__)


# http://stackoverflow.com/questions/287871/print-in-terminal-with-colors-using-python
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def mean(numbers):
    return float(sum(numbers)) / max(len(numbers), 1)


def check_results(results):
    avg = mean([X for X, _ in results])
    return avg, all([isinstance(X, Answer) for _, X in results])


def time_resolve(args, server, name, rectype, tries=3):
    """
    Time how long it takes to resolve a name using the server
    """
    resolver = Resolver()
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout
    resolver.nameservers = [server]
    results = []
    while tries > 0:
        start = time.time()
        try:
            result = resolver.query(name, rectype)
        except DNSException as ex:
            end = time.time()
            LOG.debug("%s failed in %.2fs", server, end - start)
            result = ex
        else:
            end = time.time()
            LOG.debug("%s resolved %s %s in %.2fs", server, name, rectype, end - start)
        results.append((end - start, result))
        tries -= 1
    return server, check_results(results), results


def download_resolvers():
    LOG.info("Downloading nameservers from public-dns.info")
    resp = requests.get('http://public-dns.info/nameservers.txt')
    resp.raise_for_status()
    return map(str.strip, filter(None, str(resp.text).split("\n")))


def load_resolvers(handle):
    return map(str.strip, filter(None, handle.read().split("\n")))


def check_resolver(args, resolver):
    server, (avgtime, isgood), _ = time_resolve(args, resolver, "example.com", "A")
    if args.output and isgood:
        args.output.write(server + "\n")
        args.output.flush()
    if not args.quiet:
        color = bcolors.OKGREEN if isgood else bcolors.FAIL
        print("%s%s (%.2fs)%s" % (color, server, avgtime, bcolors.ENDC))
        sys.stdout.flush()


def run(args):
    if args.download:
        resolvers = download_resolvers()
    else:
        resolvers = load_resolvers(args.resolvers)
    random.shuffle(resolvers)

    pool = gevent.pool.Pool(args.concurrency)

    bar = progressbar.ProgressBar(redirect_stdout=True, redirect_stderr=True)
    for resolver in bar(resolvers):
        pool.add(gevent.spawn(check_resolver, args, resolver))
    pool.join()


def main():
    parser = argparse.ArgumentParser(description='DNS resolver list checker')
    parser.add_argument('-o', '--output', metavar='OUTFILE',
                        type=argparse.FileType('w+'),
                        help="Output results to file")
    parser.add_argument('-r', '--resolvers', metavar='RESOLVERS_FILE',
                        default=pkg_resources.resource_stream(__name__, "resolvers.txt"),
                        type=argparse.FileType('r'),
                        help="Load DNS resolver servers from file")
    parser.add_argument('-d', '--download', action='store_true',
                        help='Download new list of resolvers from public-dns.info')
    parser.add_argument('-T', '--timeout', default=0.5, type=float, metavar='SECS',
                        help="Timeout for DNS request in seconds, default: 0.5")
    parser.add_argument('-C', '--concurrency', default=20, type=int,
                        help="Concurrent DNS requests, default: 20", metavar='N')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help="Don't print results to console")
    parser.add_argument('-v', '--verbose', action='store_const',
                        dest="loglevel", const=logging.INFO,
                        help="Log informational messages")
    parser.add_argument('--debug', action='store_const', dest="loglevel",
                        const=logging.DEBUG, default=logging.WARNING,
                        help="Log debugging messages")
    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel)

    run(args)


if __name__ == "__main__":
    main()
