#!/usr/bin/env python
"""
This script will scan all AXFR records, and compare which of the subdomains and 
record types exist in the database, incrementing the 'verify' counter.

After running this the database contains enough information to determine which 
keywords can be deleted, and which ones are useful.

The following SQL query will provide the top 1000 most effective subdomains:

    SELECT nom, GROUP_CONCAT(rec), SUM(vfy) AS total_cfy SUM(cnt) as total_cnt
    FROM axfr_counts
    GROUP BY nom
    ORDER BY total_very
    DESC LIMIT 1000;
"""
from __future__ import print_function
import sys
import os
import re
import sqlite3
from collections import defaultdict


AXFR_RE = re.compile(r'(?P<name>[^\s]+)\s+(?P<ttl>[0-9]+)\s+IN\s+(?P<type>[^\s]+)\s+(?P<args>.*)')


def update_vfy(conn, entries):
    curs = conn.cursor()
    curs.executemany('UPDATE axfr_counts SET vfy = vfy + 1 WHERE nom = ? and rec = ?', entries)
    conn.commit()


def load_file(conn, csvfile):
    print(csvfile)
    with open(csvfile, "r") as handle:
        data = handle.read()
        names = []
        for match in AXFR_RE.finditer(data, re.MULTILINE):
            names.append((match.group(1).strip('.'), match.group(3)))
        suffix = os.path.commonprefix([X[0][::-1] for X in names])[::-1]
        names = filter(lambda X: X[0],
                       [(X[0].replace(suffix, '').strip('.').lower(), X[1])
                        for X in names])
        lookup_names = []
        for name, rectype in set(names):
            if not name or name == '*':  # Ignore single wildcard or empty
                continue
            if name[:2] == '*.':  # Strip wildcard off beginning
                name = name[2:]
            lookup_names.append((name, rectype))
        update_vfy(conn, lookup_names)
        

def main():
    conn = sqlite3.connect('axfr.db')    

    csvdir = os.path.join(os.getcwd(), 'axfr')
    for filename in os.listdir(csvdir):
        load_file(conn, os.path.join(csvdir, filename))


if __name__ == "__main__":
    sys.exit(main())
