from cape_parsers.CAPE.core.IcedIDLoader import extract_config


def test_icedid():
    with open("tests/data/malware/7aaf80eb1436b946b2bd710ab57d2dcbaad2b1553d45602f2f3af6f2cfca5212", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {"CNCs": "http://anscowerbrut.com", "campaign": 2738000827}
