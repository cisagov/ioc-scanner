#!/usr/bin/env python3
"""Indicators of compromise (IoC) scanning tool.

This script can take a blob of text that "should" contain MD5 hashes
and scan a machine looking for files that match.  It will report the
location of each mataching file as well as a summary containing the
tallies by hash.  Execution time is also reported.

This script should be run as a priveledged user.
"""

# Standard Python Libraries
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
SHA256: b509f8545501588ecd828f970d91afc7c4aa6e238e838bd6a08ee2cd920fbe98
SHA-1:  31B54AEBDAF5FBC73A66AC41CCB35943CC9B7F72
SHA-1:  50973A3FC57D70C7911F7A952356188B9939E56B
SHA-1:  244EB62B9AC30934098CA4204447440D6FC4E259
SHA-1:  5C8F83CC4FF57E7C67925DF4D9DAABE5D0CC07E2
few things that should hit:
GNU bash, version 3.2.57(1)-release (x86_64-apple-darwin18)
0313fd399b143fc40cd52a1679018305
GNU bash, version 4.4.12(1)-release (x86_64-pc-linux-gnu)
ac56f4b8fac5739ccdb45777d313becf
EICAR test file
69630e4574ec6798239b091cda43dca0
"""


def setup_hashers():
    """Get hashers available in hashlib from our list of desired algorithms."""
    available_hashers = [
        algo for algo in DESIRED_HASHERS if algo in hashlib.algorithms_available
    ]
    return tuple(getattr(hashlib, algo) for algo in available_hashers)


# List of hash algorithms we want to use on files. These shoudl correspond to
# constructors in the hashlib library.
DESIRED_HASHERS = ["md5", "sha1", "sha256"]

# Hashing functions that have been verified to be available in hashlib.
AVAILABLE_HASHERS = setup_hashers()

# use word boundaries ('\b') to bracket the specific hash lengths
HASH_REGEXES = [
    r"\b([a-fA-F\d]{32})\b",  # MD5
    r"\b([a-fA-F\d]{40})\b",  # SHA-1
    r"\b([a-fA-F\d]{64})\b",  # SHA-256
]


def hash_file(file):
    """Generate supported hashes for a given file."""
    hashers = list()
    for hasher in AVAILABLE_HASHERS:
        try:
            hashers.append(hasher(usedforsecurity=False))
        # Not all implementations support the "usedforsecurity" keyword argument.
        except TypeError:
            hashers.append(hasher())

    # try except to eat filesystem errors like Permission Denied etc
    try:
        with open(file, "rb") as f:
            # read it in chunks so memory use isn't outlandish
            for chunk in iter(lambda: f.read(4096), b""):
                for hasher in hashers:
                    hasher.update(chunk)
    except OSError:
        pass

    return tuple(hasher.hexdigest() for hasher in hashers)


def main(blob=None, root="/"):
    """Start scanning, main entry point."""
    # start the clock
    start_time = datetime.utcnow()

    if blob is None:
        blob = BLOB

    # Get a list of all the hashes from some inconsiderate source.
    # We have to flatten the lists returned by re.findall() in the process.
    indicators = [match for regex in HASH_REGEXES for match in re.findall(regex, blob)]

    logging.debug("Scan will search for %d indicators", len(indicators))

    # compile a regular expression to search for all indicators
    indicators_re = re.compile("|".join(indicators))

    # start hashing files
    logging.debug("Starting scan with root: %s", root)

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

            for item in hashes:
                matches = indicators_re.findall(item)

                # tally it up and report if we get a hit
                if matches:
                    ioc_list.append(f"{item} {file}")
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
