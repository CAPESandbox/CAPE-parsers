# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.community.Amadey import extract_config


def test_amadey():
    with open("tests/data/malware/994d115922a3ce8324114199fb7d06d7c8276779f83523b66b8c05505b81376e", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "CNCs": [
                "http://85.208.84.41/f7ehhfadDSk/index.php",
                "http://76.46.157.65/07hesnhcxD/index.php"
            ],
            "version": "5.55",
            "cryptokey": "f988f0065903c81142dd38f63d7ddc4e",
            "cryptokey_type": "RC4",
            "campaign_id": "1f3bdd",
            "raw": {
                "install_dir": "29da05bd1a",
                "install_file": "Vlimvoi.exe",
            }
        }
