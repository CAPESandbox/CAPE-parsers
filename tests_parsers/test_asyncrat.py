import pytest
from cape_parsers.CAPE.community.AsyncRAT import extract_config

@pytest.mark.skip(reason="ToDo fix it")
def test_asyncrat():
    with open("tests/data/malware/f08b325f5322a698e14f97db29d322e9ee91ad636ac688af352d51057fc56526", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "raw": {
                "CNCs": ["todfg.duckdns.org"],
                "Ports": "6745",
                "Version": "0.5.7B",
                "Folder": "%AppData%",
                "Filename": "updateee.exe",
                "Install": "false",
                "Mutex": "AsyncMutex_6SI8OkPnk",
                "Pastebin": "null",
            }
        }
