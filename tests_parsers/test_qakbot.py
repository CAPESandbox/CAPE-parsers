import pytest
from cape_parsers.CAPE.core.QakBot import extract_config


@pytest.mark.skip(reason="Missed file")
def test_qakbot():
    with open("tests/data/malware/0cb0d77ac38df36fff891e072dea96401a8c1e8ff40d6ac741d5a2942aaeddbb", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {"CNCs": ["anscowerbrut.com"], "campaign": 2738000827}
