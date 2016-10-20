# DNSbrute

Fast and lightweight DNS sub-domain brute forcer, with a progres bar!

A viable alternative or companion to [subbrute](https://github.com/TheRook/subbrute), [dnscan](https://github.com/rbsec/dnscan), [massdns](https://github.com/blechschmidt/massdns), [subsearch](https://github.com/gavia/subsearch), [dnsrecon](https://github.com/darkoperator/dnsrecon), [knock](https://github.com/guelfoweb/knock), [dns_extractor](https://github.com/eliasgranderubio/dns_extractor), [Bluto](https://github.com/darryllane/Bluto), [snoopbrute](https://github.com/m57/snoopbrute), [gobuster](https://github.com/OJ/gobuster), [fierce](https://github.com/davidpepper/fierce-domain-scanner), [dnsmap](https://github.com/makefu/dnsmap), [dnsenum](https://github.com/fwaeytens/dnsenum) and [DNS-Discovery](https://github.com/m0nad/DNS-Discovery). It seems everybody and their dog has made a DNS subdomain discovery tool!

But, why is this one different? What else does it do?

## Features

 * Progress bar... awesomeness!
 * Wildcard elimination
 * JSON & text output
 * DNS resolver checker
 * Tunable retries & timeout
 * Free & liberal open-source

## TODO

 * DNS zone transfer
 * Randomized order & delay
 * Reverse DNS / PTR lookup
 * Queued processing (ZeroMQ, Beanstalkd etc)

## DNSbrute Usage

```
$ python -mdnsbrute
usage: __main__.py [-h] [-p] [-q] [-v] [--debug] [-o OUTFILE] [-j OUTJSON]
                   [-r RESOLVERS_FILE] [-n NAMES_FILE] [-d DOMAINS_FILE]
                   [-W N] [-R N] [-C N] [-T SECS]
                   [domain [domain ...]]

DNS sub-domain brute forcer

positional arguments:
  domain                One or more domains

optional arguments:
  -h, --help            show this help message and exit
  -p, --progress        Show progress bar with ETA
  -q, --quiet           Don't print results to console
  -v, --verbose         Log informational messages
  --debug               Log debugging messages
  -o OUTFILE, --output OUTFILE
                        Output results to file
  -j OUTJSON, --json OUTJSON
                        Output results, as JSON to file
  -r RESOLVERS_FILE, --resolvers RESOLVERS_FILE
                        Load DNS resolver servers from file
  -n NAMES_FILE, --names NAMES_FILE
                        Load brute-force names from file
  -d DOMAINS_FILE, --domains DOMAINS_FILE
                        Load target domains from file
  -W N, --wildcard-tests N
                        Wildcard elimination test queries, default: 3
  -R N, --retries N     Retries on failed DNS request, default: 2
  -C N, --concurrency N
                        Concurrent DNS requests, default: 20
  -T SECS, --timeout SECS
                        Timeout for DNS request in seconds, default: 1.5
```

### checkresolvers usage

```
$ python -mdnsbrute.checkresolvers
usage: checkresolvers.py [-h] [-o OUTFILE] [-D] [-T SECS] [-q] [-v] [--debug]
                         [-r RESOLVERS_FILE]

DNS resolver list checker

optional arguments:
  -h, --help            show this help message and exit
  -o OUTFILE, --output OUTFILE
                        Output results to file
  -D, --download        Download new list of resolvers from public-dns.info
  -T SECS, --timeout SECS
                        Timeout for DNS request in seconds, default: 0.5
  -q, --quiet           Don't print results to console
  -v, --verbose         Log informational messages
  --debug               Log debugging messages
  -r RESOLVERS_FILE, --resolvers RESOLVERS_FILE
                        Load DNS resolver servers from file
```

## Wordlist Generator

Included with the dnsbrute source code are a collection of tools to extract 
DNS names from Bind style zone files, these can be extracted from Dig results,
from AXFR transfer, or by scraping them from Bind config directories.

Three scripts are included:

 * `axfr.sh` - Try to perform zone transfers on the Alexa top million
 * `process-axfr.py` - Extract names and record types from zone files into SQLite DB
 * `verify-axfr.py` - Verify which extracted names match zone files

For your reference we provide a list of the top 20,000 DNS names as extracted 
from all servers in the Alexa top million which allow anonymous zone transfers ;)
