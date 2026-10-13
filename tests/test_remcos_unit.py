import logging

from cape_parsers.CAPE.core import Remcos


def test_remcos_non_pe_does_not_log_error(caplog):
    with caplog.at_level(logging.ERROR, logger=Remcos.__name__):
        assert Remcos.extract_config(b"not_a_pe_buffer") == {}
    assert "Caught an exception" not in caplog.text
