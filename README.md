# ioc-scanner 🔎🆖 #

[![Build Status](https://travis-ci.com/cisagov/ioc-scanner.svg?branch=develop)](https://travis-ci.com/cisagov/ioc-scanner)
[![Coverage Status](https://coveralls.io/repos/github/cisagov/ioc-scanner/badge.svg?branch=develop)](https://coveralls.io/github/cisagov/ioc-scanner?branch=develop)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/cisagov/ioc-scanner.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/ioc-scanner/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/cisagov/ioc-scanner.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/ioc-scanner/context:python)

The ioc-scanner can search a filesystem for indicators of compromise (IoC).
Indicators are defined by their `md5` hashes.  The tool is very flexible
about how it receives the IoC hashes.  It will search blobs of input for
strings that look like `md5` hashes.

## Command line usage ##

```bash
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

```bash
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
```

## Stand-alone usage ##

The [ioc_scanner.py](src/ioc_scan/ioc_scanner.py) was designed to be
dependency-free.  This allows it to be deployed anywhere `python3` is
available without a lengthy install process.  There is an embedded hash
list this file that can be easily edited.  This makes running the script
with tools like [Ansible](https://www.ansible.com) much simpler.

Here is an example of running the script remotely using the Ansible
[script module](https://docs.ansible.com/ansible/latest/modules/script_module.html):

```console
ansible --inventory=hosts-file cool-servers --module-name=script \
--args="src/ioc_scan/ioc_scanner.py" --become --ask-become-pass \
--user="ian.kilmister"
```

## Contributing ##

We welcome contributions!  Please see [here](CONTRIBUTING.md) for
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
