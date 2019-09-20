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
import hashlib
import logging
import os
import re
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

MD5_RE = r"\b([a-fA-F\d]{32})\b"
SHA1_RE = r"\b([a-fA-F\d]{40})\b"
SHA256_RE = r"\b([a-fA-F\d]{64})\b"


def hash_file(file):
    """Generate MD5, SHA1, and SHA256 hashes for a given file."""
    hash_md5 = hashlib.md5()  # nosec
    hash_sha1 = hashlib.sha1()  # nosec
    hash_sha256 = hashlib.sha256()

    # try except to eat filesystem errors like Permission Denied etc
    try:
        with open(file, "rb") as f:
            # read it in chunks so memory use isn't outlandish
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
                hash_sha1.update(chunk)
                hash_sha256.update(chunk)
    except OSError:
        pass
    return (hash_md5.hexdigest(), hash_sha1.hexdigest(), hash_sha256.hexdigest())


def main(blob=None, root="/"):
    """Start scanning, main entry point."""
    # start the clock
    start_time = datetime.utcnow()

    if blob is None:
        blob = BLOB

    # get a list of all the md5 hashes from some inconsiderate source.
    indicators_md5 = re.findall(MD5_RE, blob.lower())
    indicators_sha1 = re.findall(SHA1_RE, blob.lower())
    indicators_sha256 = re.findall(SHA256_RE, blob.lower())
    indicators = indicators_md5 + indicators_sha1 + indicators_sha256

    logging.debug(f"Scan will search for {len(indicators)} indicators")

    # compile a regular expression to search for all indicators
    indicators_re = re.compile("|".join(indicators))

    # start hashing files
    logging.debug(f"Starting scan with root: {root}")

    # store an array of ioc hits
    ioc_list = []
    # keep a tally of the hits
    tallies = defaultdict(lambda: 0)
    # walk the filesystem starting at root
    for rootdir, subdirs, files in os.walk(root):
        # find -xdev equivalent
        subdirs[:] = [
            d for d in subdirs if not os.path.ismount(os.path.join(rootdir, d))
        ]

        # check each file in the current directory
        for file in [os.path.join(rootdir, f) for f in files]:
            # get hashes for the current file
            hashes = hash_file(file)

            for hash in hashes:
                matches = indicators_re.findall(hash)

                # tally it up and report if we get a hit
                if matches:
                    ioc_list.append(f"{hash} {file}")
                    tallies[hash] += 1

    logging.debug("Scan completed")

    # print all indicators that were found
    for ioc in ioc_list:
        print(ioc)

    # stop the clock
    end_time = datetime.utcnow()

    print(f"Scan elapsed time: {end_time - start_time}")
    print("Hit count by indicators:")
    for indicator in indicators:
        print(f"{indicator}    {tallies[indicator]}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
