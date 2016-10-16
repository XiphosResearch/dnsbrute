#!/usr/bin/env python
"""
Converts AXFR results from Sonar from Dig format into just the subdomains and
record type. e.g:

ettoday.net.        3600    IN  TXT "v=spf1 ip4:219.85.79.135 include:_spf.google.com ~all"
ad.ettoday.net.     3600    IN  A   219.85.79.136
admin.ettoday.net.  3600    IN  CNAME   ns2.ettoday.net.
buy.ettoday.net.    3600    IN  A   219.85.79.138

Becomes

     A
    ad A
    admin CNAME
    buy A

This then needs passing to step2, which builds a probability map of the top 
most occuring words, or pairs of words, and which records are likely to exist.

For example, 'dev' is a common subdomain, but so is 'admin.dev', and
'secure.dev'.

After the list has been generated it can be tested against the original AXFR
records to provide a coverage percentage, or accuracy rating.

Download the dataset from: https://scans.io/study/hanno-axfr

Extract to current directory, leave script running for N hours, use pypy!
"""
from __future__ import print_function
import sys
import os
import re
import sqlite3
from collections import defaultdict


AXFR_RE = re.compile(r'(?P<name>[^\s]+)\s+(?P<ttl>[0-9]+)\s+IN\s+(?P<type>[^\s]+)\s+(?P<args>.*)')


def iter_names(names, maxlen=3):
    """
    Converts a list of names into many chains of names, each up to `maxlen`
    long, e.g. "www.example.com" becomes "www" "www.example" "example" etc.
    """
    for N in range(0, len(names)):
        yield names[N]
        if N < (len(names) - 1):
            for M in range(N, min(N + maxlen + 1, len(names) + 1)):
                if M - N > 1:
                    yield '.'.join(names[N:M])


def load_file(csvfile):
    with open(csvfile, "r") as handle:
        data = handle.read()
        names = []
        for match in AXFR_RE.finditer(data, re.MULTILINE):
            names.append((match.group(1).strip('.'), match.group(3)))
        suffix = os.path.commonprefix([X[0][::-1] for X in names])[::-1]
        names = filter(lambda X: X[0],
                       [(X[0].replace(suffix, '').strip('.').lower(), X[1])
                        for X in names])
        for name, rectype in set(names):
            if not name or name == '*':  # Ignore single wildcard or empty
                continue
            if name[:2] == '*.':  # Strip wildcard off beginning
                name = name[2:]
            subnames = name.split('.')
            for subname in iter_names(subnames):
                yield subname, rectype


def flush_results(conn, inserts, updates):
    curs = conn.cursor()
    curs.executemany('INSERT OR IGNORE INTO axfr_counts VALUES (?, ?, 0)', inserts)
    curs.executemany('UPDATE axfr_counts SET cnt = cnt + ? WHERE nom = ? AND rec = ?', updates)
    conn.commit()
    return [], []


def rollup_results(conn, results):    
    inserts = []
    updates = []
    flushcnt = 0
    for (name, rectype), count in results.items():
        inserts.append((name, rectype))
        updates.append((count, name, rectype))
        flushcnt += 1
        if flushcnt > 10000:
            inserts, updates = flush_results(conn, inserts, updates)
            flushcnt = 0
            print('.')
        #print(name, rectype, count)
    return defaultdict(int)


def create_table(conn):
    curs = conn.cursor()
    curs.execute("DROP TABLE IF EXISTS axfr_counts")
    curs.execute("""
    CREATE TABLE axfr_counts (
        nom TEXT NOT NULL,
        rec TEXT NOT NULL,
        cnt INTEGER NOT NULL,
        PRIMARY KEY (nom, rec)
    ) WITHOUT ROWID
    """)
    conn.commit()


def main():
    conn = sqlite3.connect('axfr.db')    
    create_table(conn)

    csvdir = os.path.join(os.getcwd(), 'axfr')
    results = defaultdict(int)
    rolling = 0
    for filename in os.listdir(csvdir):
        for subname, rectype in load_file(os.path.join(csvdir, filename)):
            results[(subname, rectype)] += 1
            rolling += 1
            if rolling > 100000:
                results = rollup_results(conn, results)
                rolling = 0
                print("!")
    results = rollup_results(conn, results)


if __name__ == "__main__":
    sys.exit(main())
