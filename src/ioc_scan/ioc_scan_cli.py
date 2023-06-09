"""Indicators of compromise (IoC) scanning tool.

This script can take a blob of text that "should" contain MD5 hashes
and scan a machine looking for files that match.  It will report the
location of each matching file as well as a summary containing the
tallies by hash.  Execution time is also reported.

This script should be run as a priveledged user.

Usage:
  ioc-scan [--log-level=LEVEL] [--stdin | --file=hashfile] [--target=root]
  ioc-scan (-h | --help)

Options:
  -h --help              Show this message.
  -f --file=hashfile     Get IOC hashes from specified file.
  -L --log-level=LEVEL   If specified, then the log level will be set to
                         the specified value.  Valid values are "debug", "info",
                         "warning", "error", and "critical". [default: warning]
  -s --stdin             Get IOC hashes from stdin.
  -t --target=root       Scan target root directory. [default: /]
"""

# Standard Python Libraries
import logging
import sys

# Third-Party Libraries
import docopt

from . import ioc_scanner
from ._version import __version__


def main() -> None:
    """Set up logging and call the ioc-scanner."""
    args = docopt.docopt(__doc__, version=__version__)
    # Set up logging
    log_level = args["--log-level"]
    try:
        logging.basicConfig(
            format="%(asctime)-15s %(levelname)s %(message)s", level=log_level.upper()
        )
    except ValueError:
        logging.critical(
            '"%s" is not a valid logging level.  Possible values '
            "are debug, info, warning, and error.",
            log_level,
        )
        sys.exit(1)

    # see if the user is providing any external hash blob data
    hashblob = None
    if args["--stdin"] is True:
        logging.debug("Reading hashes from stdin")
        hashblob = sys.stdin.read()
    elif args["--file"] is not None:
        logging.debug("Reading hashes from %s", args["--file"])
        with open(args["--file"]) as f:
            hashblob = f.read()

    exit_code = ioc_scanner.ioc_search(hashblob, args["--target"])

    # Stop logging and clean up
    logging.shutdown()

    if exit_code:
        sys.exit(exit_code)
