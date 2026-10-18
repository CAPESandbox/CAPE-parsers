import logging
from types import SimpleNamespace
from unittest.mock import patch

from cape_parsers.CAPE.core import Oyster


def test_oyster_non_pe_yara_hit_does_not_log_error(caplog):
    fake_hit = SimpleNamespace(
        rule="Oyster",
        strings=[
            SimpleNamespace(identifier="$start_exit", instances=[SimpleNamespace(offset=4)]),
            SimpleNamespace(identifier="$decode", instances=[SimpleNamespace(offset=8)]),
        ],
    )
    raw_dump = b"\x00" * 64 + "api/v1".encode("utf-16le") + b"\x00\x00" + "example.com".encode("utf-16le")
    with (
        patch.object(Oyster, "yara_scan", return_value=[fake_hit]),
        caplog.at_level(logging.ERROR, logger=Oyster.__name__),
    ):
        res = Oyster.extract_config(raw_dump)
    assert "DOS Header magic not found" not in caplog.text
    assert res["CNCs"] == ["https://example.com/api/v1"]
