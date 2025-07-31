# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.core.Zloader import extract_config


def test_zloader():
    with open("tests/data/malware/adbd0c7096a7373be82dd03df1aae61cb39e0a155c00bbb9c67abc01d48718aa", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "botnet": "Bing_Mod5",
            "campaign": "M1",
            "CNCs": ["https://dem.businessdeep.com"],
            "cryptokey": "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKGAOWVkikqE7TyKIMtWI8dFsaleTaJNXMJNIPnRE/fGCzqrV+rtY3+ex4MCHEtq2Vwppthf0Rglv8OiWgKlerIN5P6NEyCfIsFYUMDfldQTF03VES8GBIvHq5SjlIz7lawuwfdjdEkaHfOmmu9srraftkI9gZO8WRQgY1uNdsXwIDAQAB-----END PUBLIC KEY-----",
            "cryptokey_type": "Public key"
        }
