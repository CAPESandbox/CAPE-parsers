import pytest
from cape_parsers.CAPE.community.WinosStager import extract_config

@pytest.mark.xfail(reason="todo")
def test_winosstager():
    with open(
        "tests/data/malware/ed8a86bb6d3c3d907984062e3bd3d0962aa1cb481f6aaf2e36ce084f92696f2c",
        "rb",
    ) as data:
        conf = extract_config(data.read())
        assert conf == {
            "CNCs": [
                "tcp://150.5.145.84:443"
            ],
            "campaign_id": "default",
            "execution_delay_seconds": "1",
            "communication_interval_seconds": "1",
            "version": "1.0",
            "comment": "",
            "keylogger": "1",
            "end_bluescreen": "0",
            "anti_traffic_monitoring": "0",
            "entrypoint": "0",
            "process_daemon": "1",
            "process_hollowing": "0"
        }
