#!/usr/bin/env python3
"""Indicators of compromise (IoC) scanning tool.

This script can take a blob of text that "should" contain MD5 hashes
and scan a machine looking for files that match.  It will report the
location of each mataching file as well as a summary containing the
tallies by hash.  Execution time is also reported.

This script should be run as a priveledged user.
"""

from collections import defaultdict
from datetime import datetime
import logging
import platform
import re
import subprocess  # nosec
from string import Template
import sys

# just paste the text that has the indicators into BLOB.
# it will be searched, and the hashes extracted.
BLOB = """
MDS: 70a6058952ed3212217105ec7865ba21

MDS: dff4b51907018f5cf325120aec2caf45
MDS: 2d7a648ebe64e536944c011c8dcbb375
MDS: e803916dd56996d7dald4013d71d05dd
MDS: 132646a2ad9deac1944be4264da30b01
MDS: 8c109784750142b158a1459751ae5faf
MDS:  fff485a90ef0a86fb2813eb64fd3442c
MDS: bb5de4ladff67ca5fb025fa1f1835192
MDS: 2d7a648ebe64e536944c011c8dcbb375
MDS: e803916dd56996d7dald4013d71d05dd
MDS: 2a2410cef5497cbd3f6c13eaff9619da
MDS: 3e7eb6abcce304de0822a618de756fd2
MDS: 350cba65e28c723cbf0724c19bd7ee69
few things that should hit:
GNU bash, version 3.2.57(1)-release (x86_64-apple-darwin18)
0313fd399b143fc40cd52a1679018305
GNU bash, version 4.4.12(1)-release (x86_64-pc-linux-gnu)
ac56f4b8fac5739ccdb45777d313becf
EICAR test file
69630e4574ec6798239b091cda43dca0
"""

MD5_RE = r"([a-fA-F\d]{32})"
COMMANDS = {
    "Linux": Template(r"find $root -xdev -type f -exec md5sum {} \;"),
    "Darwin": Template(r"find $root -xdev -type f -exec md5 -r {} \;"),
}


def main(blob=None, root="/"):
    """Start scanning, main entry point."""
    # start the clock
    start_time = datetime.utcnow()

    if blob is None:
        blob = BLOB

    # get a list of all the md5 hashes from some inconsiderate source.
    indicators = re.findall(MD5_RE, blob.lower())
    logging.debug(f"Scan will search for {len(indicators)} indicators")

    # compile a regular expression to search for all indicators
    indicators_re = re.compile("|".join(indicators))

    # choose the correct command based on the platform, and apply root to template
    command = COMMANDS.get(platform.system()).substitute(root=root)
    logging.debug(f"Scan command: {command}")

    # start hashing files
    logging.debug(f"Starting scan with root: {root}")
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)  # nosec
    logging.debug("Scan completed")

    # keep a tally of the hits
    tallies = defaultdict(lambda: 0)

    for line in p.stdout:
        line = line.decode("utf-8")
        # a line looks like this:
        # 0313fd399b143fc40cd52a1679018305  /bin/bash

        # save just the hash
        file_hash = line.split()[0]

        # check the line for matches
        matches = indicators_re.findall(file_hash)

        # tally it up and report if we get a hit
        if matches:
            print(line)
            tallies[matches[0]] += 1

    # stop the clock
    end_time = datetime.utcnow()

    print(f"Scan elapsed time: {end_time - start_time}")
    print("Hit count by indicators:")
    for indicator in indicators:
        print(f"{indicator}    {tallies[indicator]}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
