import pytest
from cape_parsers.CAPE.community.MyKings import extract_config

@pytest.mark.xfail(reason="todo")
def test_mykings():
    with open(
        "tests/data/malware/9f51e2a881a5d53799d7aecb7afd7d220ae012040b44b212678755085888b8fb",
        "rb",
    ) as data:
        conf = extract_config(data.read())
        assert conf == {
            "CNCs": [
                "46.28.71.32",
                "108.174.197.104:777",
                "cmd1.cmd-230812.ru:9999",
                "https://pastebin.com/raw/vz9pet6K",
                "250922.duckdns.org"
            ]
        }
