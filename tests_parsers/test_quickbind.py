# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.core.Quickbind import extract_config


def test_quickbind():
    with open("tests/data/malware/bfcb215f86fc4f8b4829f6ddd5acb118e80fb5bd977453fc7e8ef10a52fc83b7", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "user_agent": "Mozilla / 4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1;.NET CLR 1.0.3705)",
            "cryptokey": "24de21a8dc08434c",
            "cryptokey_type": "RC4",
            "CNCs": ["http://185.49.69.41"],
            "mutex": "15432a4d-34ca-4d0d-a4ac-04df9a373862",
        }
