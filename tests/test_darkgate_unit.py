from unittest.mock import MagicMock, patch

from cape_parsers.CAPE.core.DarkGate import extract_config


def test_darkgate_code_section_without_raw_key():
    fake_section = MagicMock()
    fake_section.Name = b"CODE\x00\x00\x00\x00"
    fake_section.get_data.return_value = b"\x00" * 32
    fake_pe = MagicMock()
    fake_pe.sections = [fake_section]

    with patch("cape_parsers.CAPE.core.DarkGate.pefile.PE", return_value=fake_pe):
        assert extract_config(b"MZ" + b"\x00" * 64) == {}
