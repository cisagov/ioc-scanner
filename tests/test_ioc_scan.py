#!/usr/bin/env pytest -vs
"""Tests for ioc_scan."""

# Standard Python Libraries
from io import StringIO
import logging
import sys
from unittest.mock import patch

# Third-Party Libraries
import pytest

# cisagov Libraries
import ioc_scan
from ioc_scan import ioc_scan_cli, ioc_scanner

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


def test_hash_file_hashing():
    """Test that hashes are being generated correctly."""
    hashes = ioc_scanner.hash_file("tests/targets/eicar.txt")
    assert hashes[0] == "69630e4574ec6798239b091cda43dca0"
    assert hashes[1] == "cf8bd9dfddff007f75adf4c2be48005cea317c62"
    assert (
        hashes[2] == "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"
    )


def test_hash_file_except():
    """Test that hash_file() passes when an OSError exception is raised."""
    hashes = ioc_scanner.hash_file("tests/targets/doesnotexist.txt")
    # values for hashes of nothing
    assert hashes[0] == "d41d8cd98f00b204e9800998ecf8427e"
    assert hashes[1] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert (
        hashes[2] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


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
