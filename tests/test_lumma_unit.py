import struct
from unittest.mock import MagicMock, patch

import pefile

from cape_parsers.CAPE.community import Lumma


def test_lumma_unmapped_rva_in_new_keys_does_not_raise():
    fake_pe = MagicMock()
    fake_pe.OPTIONAL_HEADER.ImageBase = 0x400000
    fake_pe.get_offset_from_rva.side_effect = pefile.PEFormatError("data at RVA 0x100000 can't be fetched")
    fake_pe.sections = []

    key_pattern = (
        b"\xb8"
        + struct.pack("<I", 0x500000)
        + b"\xbf\x00\x00\x00\x00"
        + b"\xb9\x08\x00\x00\x00"
        + b"\x96\xf3\xa5\x96\xb8"
        + struct.pack("<I", 0x500100)
    )
    data = b"MZ" + b"\x00" * 62 + key_pattern + b"\x00" * 128

    with patch("cape_parsers.CAPE.community.Lumma.pefile.PE", return_value=fake_pe):
        assert Lumma.extract_config(data) is None


def test_lumma_unmapped_rva_in_encrypted_c2_does_not_raise():
    fake_pe = MagicMock()
    fake_pe.OPTIONAL_HEADER.ImageBase = 0x400000
    fake_pe.get_offset_from_rva.side_effect = [
        64,
        96,
        pefile.PEFormatError("data at RVA 0x200000 can't be fetched"),
    ]
    fake_pe.sections = []

    data = bytearray(b"MZ" + b"\x00" * 512)
    data[64:96] = b"K" * 32
    data[96:104] = b"N" * 8

    with (
        patch("cape_parsers.CAPE.community.Lumma.pefile.PE", return_value=fake_pe),
        patch(
            "cape_parsers.CAPE.community.Lumma.yara_scan_generator",
            side_effect=[iter([128]), iter([256])],
        ),
    ):
        assert Lumma.extract_config(bytes(data)) is None
