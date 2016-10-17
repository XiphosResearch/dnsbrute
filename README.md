# DNSbrute

DNS sub-domain brute forcer, written in Python, with a progres bar!

Unlike the other Python based DNS sub-domain brute forcers, this doesn't use 
multiprocessing (like subbrute, which is slow and leaves processes behind). It 
was written because we knew there was a better way to do this.

## Features

 * Wildcard elimination
 * JSON & text output
 * Progress bar
 * Tunable concurrency & timeout
 * DNS resolver checker

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
                        Concurrent DNS requests, default: 50
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