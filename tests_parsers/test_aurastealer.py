# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.core.AuraStealer import extract_config


def test_aurastealer():
    with open("tests/data/malware/bac52ffc8072893ff26cdbf1df1ecbcbb1762ded80249d3c9d420f62ed0dc202", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            'CNCs': ['https://armydevice.shop', 'https://glossmagazine.shop'],
            'user_agent': [''],
            'version': '1.0.0',
            'build': '9f594914-9bc5-422b-b4d7-8733894b0b5c',
            'cryptokey': '02220b5fef521c38dbf3e59c36b522e462a8cd36046bd01c9082e6322eacd1d1',
            'cryptokey_type': 'AES',
            'raw': {
                'iv': '816ff36da9d9627592f2618045149d22',
                'anti_vm': True,
                'anti_dbg': True,
                'self_del': True,
                'run_delay': 0
            }
        }
