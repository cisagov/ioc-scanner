# ioc-scanner 🔎🆖 #

[![GitHub Build Status](https://github.com/cisagov/ioc-scanner/workflows/build/badge.svg)](https://github.com/cisagov/ioc-scanner/actions)
[![CodeQL](https://github.com/cisagov/ioc-scanner/workflows/CodeQL/badge.svg)](https://github.com/cisagov/ioc-scanner/actions/workflows/codeql-analysis.yml)
[![Coverage Status](https://coveralls.io/repos/github/cisagov/ioc-scanner/badge.svg?branch=develop)](https://coveralls.io/github/cisagov/ioc-scanner?branch=develop)
[![Known Vulnerabilities](https://snyk.io/test/github/cisagov/ioc-scanner/develop/badge.svg)](https://snyk.io/test/github/cisagov/ioc-scanner)

The ioc-scanner can search a filesystem for indicators of compromise (IoC).
Indicators are defined by their `md5`, `sha-1`, or `sha-256` hashes.  The tool
is very flexible about how it receives the IoC hashes.  It will search blobs of
input for strings that look like `md5`, `sha-1`, and `sha-256` hashes.

## Command line usage ##

```console
Usage:
  ioc-scan [--log-level=LEVEL] [--stdin | --file=hashfile] [--target=root]
  ioc-scan (-h | --help)

Options:
  -h --help              Show this message.
  -f --file=hashfile     Search for hashes in specified file.
  -L --log-level=LEVEL   If specified, then the log level will be set to
                         the specified value.  Valid values are "debug", "info",
                         "warning", "error", and "critical". [default: warning]
  -s --stdin             Search for hashes on stdin.
  -t --target=root       Scan target root directory. [default: /]
```

## Example output ##

```console
❱ ioc-scan --target /bin
0313fd399b143fc40cd52a1679018305 /bin/bash

Scan elapsed time: 0:00:00.176262
Hit count by indicators:
70a6058952ed3212217105ec7865ba21    0
dff4b51907018f5cf325120aec2caf45    0
2d7a648ebe64e536944c011c8dcbb375    0
132646a2ad9deac1944be4264da30b01    0
8c109784750142b158a1459751ae5faf    0
fff485a90ef0a86fb2813eb64fd3442c    0
2d7a648ebe64e536944c011c8dcbb375    0
2a2410cef5497cbd3f6c13eaff9619da    0
3e7eb6abcce304de0822a618de756fd2    0
350cba65e28c723cbf0724c19bd7ee69    0
0313fd399b143fc40cd52a1679018305    1
ac56f4b8fac5739ccdb45777d313becf    0
69630e4574ec6798239b091cda43dca0    0
50973a3fc57d70c7911f7a952356188b9939e56b    0
b509f8545501588ecd828f970d91afc7c4aa6e238e838bd6a08ee2cd920fbe98    0
```

## Stand-alone usage ##

The [ioc_scanner.py](src/ioc_scan/ioc_scanner.py) file was designed to be
dependency-free.  This allows it to be deployed anywhere `python3` is
available without a full install process.  There is an embedded hash
list in this file that can be easily edited.  This makes it possible to run
this tool with automation tools like [Ansible](https://www.ansible.com).

Here is an example of running the script remotely using the Ansible
[script module](https://docs.ansible.com/ansible/latest/modules/script_module.html)
:

```console
ansible --inventory=hosts-file cool-servers \
        --module-name=ansible.builtin.script \
        --args="cmd=src/ioc_scan/ioc_scanner.py executable=python3" \
        --become --ask-become-pass --user="ian.kilmister"
```

Optionally you can use the `--file` option to use a file on the remote host as a
source for hashes.

```console
ansible --inventory=hosts-file cool-servers \
        --module-name=ansible.builtin.script \
        --args="'cmd=src/ioc_scan/ioc_scanner.py --file hash_file.txt] \
               executable=python3" \
        --become --ask-become-pass --user="ian.kilmister"
```

## Helper utilities ##

Additional helper tools and scripts are bundled with the ioc-scanner.

### `stix-extract` ###

```console
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
```

The `stix-extract` utility can be used alone or in conjunction with the
`ioc-scan` tool to scan for IoCs in a STIX file.

```console
curl https://www.cisa.gov/sites/default/files/2023-06/aa23-158a.stix_.xml \
| stix-extract | ioc-scan --stdin --target=.
```

### `ioc_scan_by_host.sh` ###

To scan for indicator strings on AWS instances that are accessible via
[SSM](https://docs.aws.amazon.com/systems-manager/latest/userguide/what-is-systems-manager.html),
the `ioc_scan_by_host.sh` shell script has been provided in the `extras`
directory:

```console
$ ./extras/ioc_scan_by_host.sh my-ioc-strings.txt i-0123456789abcdef0

IOC List is: "192.168.1[.]1 sketchy-site[.]org IOC_STRING_1 IOC_STRING_2"
Instances are: "i-0123456789abcdef0"

Searching i-0123456789abcdef0:

Starting session with SessionId: iam.username-0123456789abcdef0
0 found for 192.168.1[.]1
0 found for sketchy-site[.]org
0 found for IOC_STRING_1
0 found for IOC_STRING_2

Exiting session with sessionId: iam.username-0123456789abcdef0.

Search of i-0123456789abcdef0 is complete.
```

## Contributing ##

We welcome contributions!  Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for
details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
