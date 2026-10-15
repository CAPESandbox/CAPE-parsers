from unittest.mock import MagicMock, patch

from cape_parsers.CAPE.core import BlackDropper


def test_blackdropper_peformaterror_handled_gracefully():
    # Invalid PE / non-PE data should return {} and not raise pefile.PEFormatError
    res = BlackDropper.extract_config(b"NOT_A_PE_FILE_CORRUPTED_OR_DUMP")
    assert res == {}


def test_blackdropper_valid_mock_pe_extraction():
    fake_pe = MagicMock()
    fake_pe.FILE_HEADER.TimeDateStamp = 1715000000  # 2024

    section = MagicMock()
    section.Name = b".rdata\x00\x00"
    # Builder.dll pattern with padding
    section.get_data.return_value = b"\x00" * 100 + b"Builder.dll\x00" + b"\x00" * 100
    fake_pe.sections = [section]

    with patch("cape_parsers.CAPE.core.BlackDropper.pefile.PE", return_value=fake_pe):
        res = BlackDropper.extract_config(b"MZ" + b"\x00" * 512)
        assert isinstance(res, dict)
