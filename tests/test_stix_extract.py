"""Test the stix_extract module."""
# Standard Python Libraries
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

# Third-Party Libraries
import pytest

# cisagov Libraries
import ioc_scan
from ioc_scan import stix_extract
from ioc_scan.stix_extract import extract_stix_info, sort_ip_address

PROJECT_VERSION = ioc_scan.__version__


def test_extract_stix_info_ip():
    """Test extracting IP addresses from a STIX package."""
    observable_mock = MagicMock()
    observable_mock.object_.properties._XSI_TYPE = "AddressObjectType"
    observable_mock.object_.properties.address_value = "127.0.0.1"
    indicator_mock = MagicMock()
    indicator_mock.observables = [observable_mock]
    stix_package_mock = MagicMock()
    stix_package_mock.indicators = [indicator_mock]
    with patch(
        "ioc_scan.stix_extract.STIXPackage.from_xml", return_value=stix_package_mock
    ):
        ip_addresses, hashes, fqdns, urls = extract_stix_info("stix_file")
    assert ip_addresses == ["127.0.0.1"]
    assert hashes == []
    assert fqdns == []
    assert urls == []


def test_sort_ip_address():
    """Test sorting IP addresses."""
    result = sort_ip_address("127.0.0.1")
    assert result == (4, 2130706433)


@pytest.fixture
def mock_domain_observable():
    """Return a mock STIX DomainNameObjectType observable."""
    observable = MagicMock()
    observable.object_.properties._XSI_TYPE = "DomainNameObjectType"
    observable.object_.properties.value.value = "www.example.com"
    return observable


@pytest.fixture
def mock_uri_observable():
    """Return a mock STIX URIObjectType observable."""
    observable = MagicMock()
    observable.object_.properties._XSI_TYPE = "URIObjectType"
    observable.object_.properties.value.value = "www.example.com/path"
    return observable


def test_extract_stix_info_with_domain_and_uri_observables(
    mock_domain_observable, mock_uri_observable
):
    """Test extracting FQDNs and URLs from a STIX package."""
    stix_package_mock = MagicMock()
    stix_package_mock.indicators = [
        MagicMock(observables=[mock_domain_observable, mock_uri_observable])
    ]
    with patch(
        "ioc_scan.stix_extract.STIXPackage.from_xml", return_value=stix_package_mock
    ):
        ips, hashes, fqdns, urls = extract_stix_info("fake_file.xml")
    assert fqdns == ["www.example.com"]
    assert urls == ["www.example.com/path"]


@pytest.fixture
def mock_hash_observable_with_valid_types():
    """Return a mock STIX FileObjectType observable with valid hash types."""
    observable = MagicMock()
    observable.object_.properties._XSI_TYPE = "FileObjectType"
    observable.object_.properties.hashes = [
        MagicMock(
            type_=MagicMock(value="SHA1"),
            simple_hash_value=MagicMock(value="SHA1_HASH"),
        ),
        MagicMock(
            type_=MagicMock(value="MD5"), simple_hash_value=MagicMock(value="MD5_HASH")
        ),
        MagicMock(
            type_=MagicMock(value="SHA256"),
            simple_hash_value=MagicMock(value="SHA256_HASH"),
        ),
    ]
    return observable


@pytest.fixture
def mock_hash_observable_with_invalid_types():
    """Return a mock STIX FileObjectType observable with invalid hash types."""
    observable = MagicMock()
    observable.object_.properties._XSI_TYPE = "FileObjectType"
    observable.object_.properties.hashes = [
        MagicMock(
            type_=MagicMock(value="INVALID1"),
            simple_hash_value=MagicMock(value="INVALID1_HASH"),
        ),
        MagicMock(
            type_=MagicMock(value="INVALID2"),
            simple_hash_value=MagicMock(value="INVALID2_HASH"),
        ),
        MagicMock(
            type_=MagicMock(value="INVALID3"),
            simple_hash_value=MagicMock(value="INVALID3_HASH"),
        ),
    ]
    return observable


@pytest.mark.parametrize(
    "hash_observable, expected",
    [
        ("mock_hash_observable_with_valid_types", ["SHA256_HASH"]),
        ("mock_hash_observable_with_invalid_types", []),
    ],
)
def test_extract_stix_info_with_hash_observable(hash_observable, expected, request):
    """Test extracting hashes from a STIX package."""
    mock_hash_observable = request.getfixturevalue(hash_observable)
    stix_package_mock = MagicMock()
    stix_package_mock.indicators = [MagicMock(observables=[mock_hash_observable])]
    with patch(
        "ioc_scan.stix_extract.STIXPackage.from_xml", return_value=stix_package_mock
    ):
        ips, hashes, fqdns, urls = extract_stix_info("fake_file.xml")
    assert hashes == expected


def test_extract_stix_info_with_invalid_stix_file():
    """Test invalid filename."""
    with pytest.raises(Exception):
        extract_stix_info("invalid.stix")


def test_extract_stix_info_with_unexpected_object_type():
    """Test extracting observables from a STIX package with an unexpected object type."""
    observable_mock = MagicMock()
    observable_mock.object_.properties._XSI_TYPE = "UnexpectedObjectType"
    indicator_mock = MagicMock()
    indicator_mock.observables = [observable_mock]
    stix_package_mock = MagicMock()
    stix_package_mock.indicators = [indicator_mock]
    with patch(
        "ioc_scan.stix_extract.STIXPackage.from_xml", return_value=stix_package_mock
    ):
        ip_addresses, hashes, fqdns, urls = extract_stix_info("stix_file")
    assert ip_addresses == []
    assert hashes == []
    assert fqdns == []
    assert urls == []


def test_extract_stix_info_with_file_object_without_hashes():
    """Test extracting observables from a STIX package where the file object does not have hashes."""
    observable_mock = MagicMock()
    observable_mock.object_.properties._XSI_TYPE = "FileObjectType"
    observable_mock.object_.properties.hashes = None
    indicator_mock = MagicMock()
    indicator_mock.observables = [observable_mock]
    stix_package_mock = MagicMock()
    stix_package_mock.indicators = [indicator_mock]
    with patch(
        "ioc_scan.stix_extract.STIXPackage.from_xml", return_value=stix_package_mock
    ):
        ip_addresses, hashes, fqdns, urls = extract_stix_info("stix_file")
    assert ip_addresses == []
    assert hashes == []
    assert fqdns == []
    assert urls == []


def test_version(capsys):
    """Verify that version string sent to stdout, and agrees with the module."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            stix_extract.main()
    captured = capsys.readouterr()
    assert (
        captured.out == f"{PROJECT_VERSION}\n"
    ), "standard output by '--version' should agree with module.__version__"


def test_help(capsys):
    """Verify that the help text is sent to stdout."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--help"]):
            stix_extract.main()
    captured = capsys.readouterr()
    assert (
        "This script parses" in captured.out
    ), "help text did not have expected string"


def test_main():
    """Test the main function of the script."""
    # Mock the command line arguments
    with patch("ioc_scan.stix_extract.docopt") as mock_docopt:
        # Create a temporary STIX file
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.write(b"<xml></xml>")  # Minimal XML content to prevent parse errors
        temp_file.close()

        mock_docopt.return_value = {"<file>": temp_file.name}

        # Mock the extraction function to return some test data
        with patch("ioc_scan.stix_extract.extract_stix_info") as mock_extract:
            mock_extract.return_value = (
                ["1.1.1.1", "2.2.2.2"],
                ["hash1", "hash2"],
                ["fqdn1", "fqdn2"],
                ["url1", "url2"],
            )

            # Mock the print function to do nothing
            with patch("builtins.print") as mock_print:
                stix_extract.main()

        # Verify the mock calls.
        mock_docopt.assert_called_once_with(
            stix_extract.__doc__, version=PROJECT_VERSION
        )
        mock_extract.assert_called_once_with(temp_file.name)
        assert mock_print.call_count == 12  # Check how many times print is called

        os.unlink(temp_file.name)  # Delete the temporary file
