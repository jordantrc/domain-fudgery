#!/usr/bin/env python3
#
# fudge-domain.py
#
# Finds potentially useful domains
# which are visually similar to the 
# target domain and ascertains whether
# these domains are currently available
# (not registered). Also checks if any TLDs
# are not registered for the domain.
#
# Usage:
# domain-fudgery.py [options] [domain]
# Options:
#   --no-whois:     do not perform whois checks
#   --file:         load domains from the given filename
#

import argparse
import dns
import os
import sys


def main():
    """Main function."""
    # defaults
    whois = True
    load_file = None

    parser = argparse.ArgumentParser(description="Finds fudged domains.")
    parser.add_argument("--no-whois", action='store_true', dest="no_whois", help="disable whois queries")
    parser.add_argument("--file", dest="file", help="file containing DNS names to load")
    parser.add_argument("domain", nargs='*', help="domain to fudge")
    args = parser.parse_args()

    # argument logic checks
    if args.no_whois:
        whois = False

    if args.file:
        if os.path.isfile(args.file):
            load_file = args.file
        else:
            print("[-] file not found or permission denied")
            sys.exit(1)




if __name__ == "__main__":
    main()