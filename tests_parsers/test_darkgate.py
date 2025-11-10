from cape_parsers.CAPE.core.DarkGate import extract_config


def test_darkgate():
    with open("tests/data/malware/1c3ae64795b61034080be00601b947819fe071efd69d7fc791a99ec666c2043d", "rb") as data:
        assert extract_config(data.read()) == {
            "CNCs": ["http://80.66.88.145:2842"],
            "raw": {
                "c2_port": "2842",
                "startup_persistence": "Yes",
                "rootkit": "Yes",
                "anti_vm": "No",
                "check_disk": "No",
                "min_disk": "35",
                "anti_analysis": "No",
                "check_ram": "No",
                "min_ram": "4096",
                "check_xeon": "No",
                "internal_mutex": "aFcade",
                "crypter_rawstub": "No",
                "crypter_dll": "No",
                "crypter_au3": "Yes",
                "unknown_14": "4",
                "crypto_key": "SygEDGfHvmMftg",
                "c2_ping_interval": "4",
                "anti_debug": "No",
                "unknown_18": "Yes",
                "BSOD_protect": "Yes",
                "unknown_20": "Yes",
            },
            "mutex": "aFcade",
            "cryptokey": "SygEDGfHvmMftg",
        }
