# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.community.Lumma import extract_config


def test_lumma():
    with open("tests/data/malware/5d58bc449693815f6fb0755a364c4cd3a8e2a81188e431d4801f2fb0b1c2de8f", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "C2": [
                "delaylacedmn.site",
                "writekdmsnu.site",
                "agentyanlark.site",
                "bellykmrebk.site",
                "underlinemdsj.site",
                "commandejorsk.site",
                "possiwreeste.site",
                "famikyjdiag.site",
                "agentyanlark.site",
            ],
            'Build ID': 'z9sSW4--'
        }
