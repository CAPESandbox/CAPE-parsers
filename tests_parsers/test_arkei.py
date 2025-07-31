# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.community.Arkei import extract_config


def test_arkei():
    with open("tests/data/malware/69ba4e2995d6b11bb319d7373d150560ea295c02773fe5aa9c729bfd2c334e1e", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "CNCs": ["http://coin-file-file-19.com/tratata.php"],
            "botnet": "Default"
        }
