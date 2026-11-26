# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.community.LimeRAT import extract_config


def test_limerat_key_nulled():
    with open("tests/data/malware/0794bc31d71174be2e372f0166e041f1a6653d63df29f9aebf19233e477ea9b2", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "cryptokey": "d7d2cf2fa2bf0bd7f8cf0095189d28d7d2cf2fa2bf0bd7f8cf0095189d286100",
            "cryptokey_type": "AES",
            "raw": {
                "config_url": "https://pastebin.com/raw/cXuQ0V20",
                "encryption_key": "nulled",
                "endof": "|'N'|",
                "split": "|'L'|",
                "exe": "Winservices.exe",
                "usb": True,
                "pin": False,
                "anti": True,
                "drop": False,
                "path1": "AppData",
                "path2": "\\",
                "btc_address": "1JBKLGyE6AnRGvk92A8x3m8qmXfh3fcEty",
                "downloader_once": False,
                "download_link": "",
                "delay": 3,
                "config_url_type": "dead_drop",
            },
            "CNCs": ["https://pastebin.com:443/raw/cXuQ0V20"],
        }


def test_limerat_key_cryhacker():
    with open("tests/data/malware/ba870136fc03dee7dd8df18b7e5ddf7e6a67bff8da174f0e89893aae83dc48ca", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "cryptokey": "323d9e36040d1be5944a4b586afb62323d9e36040d1be5944a4b586afb62d300",
            "cryptokey_type": "AES",
            "raw": {
                "config_url": "https://pastebin.com/raw/Jv1P4zmq",
                "encryption_key": "cryhacker360@123",
                "endof": "|'N'|",
                "split": "|'L'|",
                "exe": "svchost.exe",
                "usb": True,
                "pin": True,
                "anti": True,
                "drop": True,
                "path1": "AppData",
                "path2": "\\",
                "btc_address": "3NWxjG7nS4fWaog4aS1bS6v5sMdqsvPQbG",
                "downloader_once": False,
                "download_link": "",
                "delay": 36,
                "config_url_type": "dead_drop",
            },
            "CNCs": ["https://pastebin.com:443/raw/Jv1P4zmq"],
        }


def test_limerat_key_base64():
    with open("tests/data/malware/530c04796fc67bbc79c7685ab50bf7f3c26946952afcb83bb077814bc782f0ac", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "cryptokey": "79deab8e204439ff451b9bd4441f9079deab8e204439ff451b9bd4441f90c600",
            "cryptokey_type": "AES",
            "raw": {
                "config_url": "https://pastebin.com/GDMTYe53",
                "encryption_key": "obLD1OX2BxgpMEpbbH2On6Gyw9Tl9gcYKTBKW2x9jp8=",
                "endof": "|'N'|",
                "split": "|'L'|",
                "exe": "cec.co.com.exe",
                "usb": True,
                "pin": True,
                "anti": True,
                "drop": True,
                "path1": "AppData",
                "path2": "\\",
                "btc_address": "",
                "downloader_once": True,
                "download_link": "https://cec.co.com/",
                "delay": 3,
                "config_url_type": "dead_drop",
            },
            "CNCs": ["https://pastebin.com:443/GDMTYe53"],
        }


def test_limerat_oalabs_reference():
    # Expected values match OALabs' published output for this sample (same SHA256).
    # https://github.com/OALabs/research/blob/master/_notebooks/2023-08-17-limerat.ipynb
    with open("tests/data/malware/024cce95a63124cd3cbfe3f21fbacf8437fd288717fce379006064aa2a97641e", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "cryptokey": "4823ed16951e7debcf8570cf0d37774823ed16951e7debcf8570cf0d37775100",
            "cryptokey_type": "AES",
            "raw": {
                "config_url": "https://pastebin.com/raw/LJe9sUk5",
                "encryption_key": "NYANCAT",
                "endof": "|'N'|",
                "split": "|'L'|",
                "exe": "Wservices.exe",
                "usb": True,
                "pin": False,
                "anti": False,
                "drop": False,
                "path1": "Temp",
                "path2": "\\",
                "btc_address": "1B5aLZh6psoQttLGn9tpbdibiWqzyh4Jfv",
                "downloader_once": False,
                "download_link": "",
                "delay": 3,
                "config_url_type": "dead_drop",
            },
            "CNCs": ["https://pastebin.com:443/raw/LJe9sUk5"],
        }


def test_limerat_invalid_inputs():
    assert extract_config(b"") == {}
    assert extract_config(b"not a PE file") == {}
    assert extract_config(b"\x00" * 128) == {}
    assert extract_config(bytes(range(256)) * 8) == {}
    with open("tests/data/malware/0794bc31d71174be2e372f0166e041f1a6653d63df29f9aebf19233e477ea9b2", "rb") as data:
        assert extract_config(data.read()[:2000]) == {}
