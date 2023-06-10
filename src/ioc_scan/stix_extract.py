#!/usr/bin/env python3

"""
Extract valuable information from STIX (Structured Threat Information Expression) files.

This script parses the STIX file to extract and print the following observables:
- IP addresses, which are associated with network indicators.
- Hashes (SHA256, SHA1, MD5) of files, prioritizing by hash type.
- Fully Qualified Domain Names (FQDNs), which can help identify associated domains.
- URLs, which could represent potential threat sources or command and control servers.

The script prints each observable type in a separate section with a clear title for easy reading.

Usage:
    stix-extract [<file>]

Options:
    -h --help   Show this screen.

Arguments:
    file        The path to the STIX xml file to parse. If not specified, reads from standard input.
"""

# Standard Python Libraries
from collections import OrderedDict
from io import TextIOWrapper
import ipaddress
import sys

# Third-Party Libraries
from docopt import docopt
from stix.core import STIXPackage

from ._version import __version__


def extract_stix_info(stix_file):
    """
    Extract valuable information (IP addresses, hashes, FQDNs, and URLs) from a STIX file.

    Prioritize hashes based on their type: SHA256 > SHA1 > MD5.

    Args:
        stix_file (str): path to the STIX file to parse

    Returns:
        tuple: a tuple containing four lists - one for IP addresses, one for hashes, one for FQDNs, and one for URLs.
    """
    # Load the STIX package from the XML file
    try:
        stix_package = STIXPackage.from_xml(stix_file)
    except Exception as e:
        sys.stderr.write(f"Error parsing STIX file: {e}")
        raise e

    # Initialize lists to store IP addresses, hashes, FQDNs, and URLs
    ip_addresses = []
    hashes = []
    fqdns = []
    urls = []

    # Define hash type priority. Lower value means higher priority.
    hash_priority = OrderedDict([("SHA256", 0), ("SHA1", 1), ("MD5", 2)])

    # Iterate over each indicator in the STIX package
    for indicator in stix_package.indicators:
        for observable in indicator.observables:
            object_type = observable.object_.properties._XSI_TYPE
            if object_type == "AddressObjectType":
                # Convert cybox.common.properties.String to str
                ip_addresses.append(str(observable.object_.properties.address_value))
            elif object_type == "FileObjectType":
                hashes_dict = observable.object_.properties.hashes
                if hashes_dict:
                    best_hash = None
                    best_priority = float("inf")
                    for h in hashes_dict:
                        if (
                            h.type_.value in hash_priority
                            and hash_priority[h.type_.value] < best_priority
                        ):
                            best_hash = str(h.simple_hash_value.value)  # Convert to str
                            best_priority = hash_priority[h.type_.value]
                    if best_hash is not None:
                        hashes.append(best_hash)
            elif object_type == "DomainNameObjectType":
                # Convert cybox.common.properties.String to str
                fqdns.append(str(observable.object_.properties.value.value))
            elif object_type == "URIObjectType":
                # Convert cybox.common.properties.String to str
                urls.append(str(observable.object_.properties.value.value))

    return ip_addresses, hashes, fqdns, urls


def sort_ip_address(ip):
    """
    Take an IP address as input and return a tuple that can be used for sorting.

    Args:
        ip (str): an IP address

    Returns:
        tuple: a tuple containing two elements - the IP version (int) and the integer representation of the IP address (int).
    """
    ip_obj = ipaddress.ip_address(ip)
    return (ip_obj.version, int(ip_obj))


def main():
    """Parse command line arguments and extract information from the STIX file."""
    # Parse command line arguments
    args = docopt(__doc__, version=__version__)
    # Extract data from the STIX file or from stdin
    stix_file = (
        args["<file>"]
        if args["<file>"]
        else TextIOWrapper(sys.stdin.buffer, encoding="utf-8")
    )
    # Extract data from the STIX file
    ip_addresses, hashes, fqdns, urls = extract_stix_info(stix_file)
    # Sort IP addresses naturally (by their integer representation)
    ip_addresses.sort(key=sort_ip_address)
    hashes.sort()
    fqdns.sort()
    urls.sort()
    # Print IPs, hashes, FQDNs, and URLs with separators and titles
    print(f"\n{'#' * 20}\n# IP Addresses\n{'#' * 20}\n")
    for ip in ip_addresses:
        print(ip)
    print(f"\n{'#' * 20}\n# Hashes\n{'#' * 20}\n")
    for hash in hashes:
        print(hash)
    print(f"\n{'#' * 20}\n# FQDNs\n{'#' * 20}\n")
    for fqdn in fqdns:
        print(fqdn)
    print(f"\n{'#' * 20}\n# URLs\n{'#' * 20}\n")
    for url in urls:
        print(url)


if __name__ == "__main__":
    sys.exit(main())
