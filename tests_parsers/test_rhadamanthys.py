# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.core.Rhadamanthys import extract_config


def test_rhadamanthys():
    with open("tests/data/malware/aec7e18e752d06b62ecf48a392dacb9e0ca476ade84f01c1f5114536e22207f8", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "CNCs": [
                "https://185.198.234.232/apichk/bief8u31.ao3gp",
                "https://104.164.55.233/apichk/bief8u31.ao3gp",
                "https://103.245.231.203/apichk/bief8u31.ao3gp"
            ]
        }
