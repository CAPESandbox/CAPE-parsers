import logging
from types import SimpleNamespace
from unittest.mock import patch

from Cryptodome.Cipher import ARC4

from cape_parsers.CAPE.core import Remcos


def test_remcos_non_pe_does_not_log_error(caplog):
    with caplog.at_level(logging.ERROR, logger=Remcos.__name__):
        assert Remcos.extract_config(b"not_a_pe_buffer") == {}
    assert "Caught an exception" not in caplog.text


def test_remcos_rcdata_without_delimiter_returns_empty(caplog):
    key = b"k"
    plaintext = b"a\xd0b:80:pass|extra_without_remcos_delimiter"
    blob = bytes([len(key)]) + key + ARC4.new(key).decrypt(plaintext)
    with (
        patch.object(Remcos.pefile, "PE", return_value=SimpleNamespace()),
        patch.object(Remcos, "get_rsrc", return_value=[("RT_RCDATA", blob, len(blob), None)]),
        caplog.at_level(logging.ERROR, logger=Remcos.__name__),
    ):
        assert Remcos.extract_config(b"MZ_fake_pe") == {}
    assert "Caught an exception" not in caplog.text


def test_remcos_invalid_utf8_in_c2_does_not_log_error(caplog):
    key = b"k"
    plaintext = b"a\xd0b:80:pass|extra|\x1e\x1e\x1f|botnet"
    blob = bytes([len(key)]) + key + ARC4.new(key).decrypt(plaintext)
    with (
        patch.object(Remcos.pefile, "PE", return_value=SimpleNamespace()),
        patch.object(Remcos, "get_rsrc", return_value=[("RT_RCDATA", blob, len(blob), None)]),
        caplog.at_level(logging.ERROR, logger=Remcos.__name__),
    ):
        assert Remcos.extract_config(b"MZ_fake_pe") == {}
    assert "Caught an exception" not in caplog.text
