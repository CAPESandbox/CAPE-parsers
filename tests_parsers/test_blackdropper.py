# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.core.BlackDropper import extract_config

def test_blackdropper():
    with open("tests/data/malware/f8026ae3237bdd885e5fcaceb86bcab4087d8857e50ba472ca79ce44c12bc257", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "CNCs": ["http://72.5.42.222:8568/api/dll/", "http://72.5.42.222:8568/api/fileZip"],
            "campaign": "oFwQ0aQ3v",
            "raw": {"directories": ["\\Music\\dkcydqtwjv"]}
        }
