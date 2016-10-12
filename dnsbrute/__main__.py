from __future__ import print_function
import sys
import pkg_resources
import argparse
from . import DNSBrute, DNSNameTester


def main():
	parser = argparse.ArgumentParser(description='DNS sub-domain brute forcer')
	parser.add_argument('-R', '--resolvers', metavar='RESOLVERS_FILE',
		default=pkg_resources.resource_stream(__name__, "resolvers.txt"),
		type=argparse.FileType('r'), help="Load DNS resolver servers from file")
	parser.add_argument('-n', '--names', metavar='NAMES_FILE',
		default=pkg_resources.resource_stream(__name__, "names_small.txt"),
		type=argparse.FileType('r'), help="Load brute-force names from file")
	parser.add_argument('-d', '--domains', metavar='DOMAINS_FILE',
		type=argparse.FileType('r'), help="Load target domains from file")
	parser.add_argument('-r', '--retries', default=2, type=int,
		help="Retries on failed DNS request, default: 2")
	parser.add_argument('-c', '--concurrency', default=20, type=int,
		help="Concurrent DNS requests, default: 50")
	parser.add_argument('-t', '--timeout', default=1.5, type=float,
		help="Timeout for DNS request in seconds, default: 1.5")
	parser.add_argument('-p', '--progress', action='store_true')
	parser.add_argument('domain', nargs='*', help='One or more domains')
	args = parser.parse_args()
	bruter = DNSBrute(args)
	if not bruter.valid():
		parser.print_help()
		return 1
	bruter.run()
	return 0


if __name__ == "__main__":
	sys.exit(main())
