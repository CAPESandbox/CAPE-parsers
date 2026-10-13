import logging

from cape_parsers.CAPE.community import SparkRAT


def test_sparkrat_missing_config_logs_debug(caplog):
    with caplog.at_level(logging.ERROR, logger=SparkRAT.__name__):
        assert SparkRAT.extract_config(b"no_config_marker_here") == {}
    assert "Configuration is not found." not in caplog.text
