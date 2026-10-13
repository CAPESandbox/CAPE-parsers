# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.core.BumbleBee import extract_config


def test_bumblebee():
    with open("tests/data/malware/f8a6eddcec59934c42ea254cdd942fb62917b5898f71f0feeae6826ba4f3470d", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {"botnet": "YTBSBbNTWU", "campaign": "1904r", "CNCs": ["444"], "raw": {"Data": "XNgHUGLrCD"}}
