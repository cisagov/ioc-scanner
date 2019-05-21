#!/usr/bin/env pytest -vs
"""Tests for ioc_scan."""

from io import StringIO
from unittest.mock import patch
import logging
import sys

import pytest

import ioc_scan
from ioc_scan import ioc_scan_cli


log_levels = (
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    pytest.param("critical2", marks=pytest.mark.xfail),
)


def test_version(capsys):
    """Verify that version string sent to stdout, and agrees with the module."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            ioc_scan_cli.main()
    captured = capsys.readouterr()
    assert (
        captured.out == f"{ioc_scan.__version__}\n"
    ), "standard output by '--version' should agree with module.__version__"


@pytest.mark.parametrize("level", log_levels)
def test_log_levels(level):
    """Validate commandline log-level arguments."""
    with patch.object(
        sys, "argv", ["bogus", f"--log-level={level}", "--target=tests/targets"]
    ):
        with patch.object(logging.root, "handlers", []):
            assert (
                logging.root.hasHandlers() is False
            ), "root logger should not have handlers yet"
            return_code = ioc_scan_cli.main()
            assert (
                logging.root.hasHandlers() is True
            ), "root logger should now have a handler"
            assert return_code == 0, "main() should return success (0)"


def test_scan_file(capsys):
    """Test running the scanner with an input target file."""
    with patch.object(
        sys,
        "argv",
        [
            "bogus",
            "--log-level=debug",
            "--file=tests/testblob.txt",
            "--target=tests/targets",
        ],
    ):
        ioc_scan_cli.main()
    captured = capsys.readouterr()
    print(captured.out)
    assert (
        captured.out.count("eicar.txt") == 1
    ), "standard out should contain eicar detection with filename"
    assert (
        captured.out.count("69630e4574ec6798239b091cda43dca0") == 2
    ), "standard out should detection and tally should match hash"


def test_scan_stdin(capsys):
    """Test running the scanner with an input target file."""
    with patch.object(
        sys, "argv", ["bogus", "--log-level=debug", "--stdin", "--target=tests/targets"]
    ):
        with patch("sys.stdin", StringIO("69630e4574ec6798239b091cda43dca0")):
            ioc_scan_cli.main()
    captured = capsys.readouterr()
    print(captured.out)
    assert (
        captured.out.count("eicar.txt") == 1
    ), "standard out should contain eicar detection with filename"
    assert (
        captured.out.count("69630e4574ec6798239b091cda43dca0") == 2
    ), "standard out should detection and tally should match hash"
