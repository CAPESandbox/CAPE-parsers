from cape_parsers.CAPE.community.Carbanak import extract_config


def test_carbanak():
    with open("tests/data/malware/c9c1b06cb9c9bd6fc4451f5e2847a1f9524bb2870d7bb6f0ee09b9dd4e3e4c84", "rb") as data:
        assert extract_config(data.read()) == {
            "version": "1.7",
            "raw": {"Unknown 1": "60", "Unknown 2": "xoR9jtbNLlyJWw3dDRho7tqI8aRY5n"},
            "CNCs": ["https://5.161.223.210:443", "https://207.174.30.226:443"],
            "campaign": "rabt11901b_x64",
        }
