#!/usr/bin/env python
import sys
import collections
import heapq
import operator
import re

levels = {
     'kr': -3,
     'jp': -3,
     'uk': -3,
     'mil': -3,
     'cn': -2,
     'co': -2,
     'ca': -2,
     'us': -2,
     'es': -2,
    'com': -2,
    'org': -2,
    'gov': -2,
    'net': -2,
    'edu': -2,
}

ipregex = r"(?P<ip>((25[0-5]|2[0-4]\d|[01]\d\d|\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]\d\d|\d?\d))"
ipregex = re.compile(ipregex)

def simplify(hostname):

    if ipregex.match(hostname):
        return '.'.join(hostname.split(".")[0:3])

    parts = hostname.split(".")

    idx = levels.get(parts[-1])
    if idx:
        return '.'.join(parts[idx:])
    return hostname



def main():
    hosts = collections.defaultdict(int)
    for line in sys.stdin:
        if line.startswith("#"): continue

        parts = line.split("\t")
        host = parts[8]
        size = parts[13]

        if host == '-': continue

        hosts[simplify(host)] += int(size)

    largest = heapq.nlargest(20, hosts.iteritems(), key=operator.itemgetter(1))
    for host, bytes in largest:
        print host, bytes/1024/1024/1024.0


if __name__ == "__main__":
    main()
