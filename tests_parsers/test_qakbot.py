import pytest

from cape_parsers.CAPE.core.QakBot import extract_config


@pytest.mark.skip(reason="Missed file")
def test_qakbot():
    with open("tests/data/malware/59559e97962e40a15adb2237c4d01cfead03623aff1725616caeaa5a8d273a35", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "raw": {
                "C2s": ["62.204.41.234:2222", "77.105.162.176:995", "31.210.173.10:443", "5.252.177.195:443"],
                "Exe timestamp": "18:14:52 20-03-2024",
            },
            "CNCs": [
                "http://62.204.41.234:2222",
                "http://77.105.162.176:995",
                "http://31.210.173.10:443",
                "http://5.252.177.195:443",
            ],
        }
