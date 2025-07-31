# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.community.Lumma import extract_config


def test_lumma():
    with open("tests/data/malware/ede02b81615e9011835b26039b5963db0eb9c4569e5535da58c6aefa7c1b7217", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "CNCs": [
                "roriwfq.xyz/auyw",
                "narrathfpt.top/tekq",
                "escczlv.top/bufi",
                "localixbiw.top/zlpa",
                "korxddl.top/qidz",
                "stochalyqp.xyz/alfp",
                "diecam.top/laur",
                "citellcagt.top/gjtu",
                "saokwe.xyz/plxa",
            ],
            "Build ID": "490cef3c0ae4b5f900506d5988954245474b4975ef"
        }
