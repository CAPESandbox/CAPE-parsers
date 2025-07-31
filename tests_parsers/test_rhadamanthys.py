# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.core.Rhadamanthys import extract_config


def test_rhadamanthys():
    with open("tests/data/malware/b70519d6094fa55da2b86d897be0040ee84d0b3ef61ab4fd8d08a20628a67497", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "raw": {"Reexecution_delay": 0},
            "CNCs": [
                "https://51.75.171.9:5151/9640d96bbead45f349f3ab9/Xteam30.api"
            ]
        }
