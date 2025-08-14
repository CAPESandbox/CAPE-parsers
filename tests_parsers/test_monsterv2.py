import pytest
from cape_parsers.CAPE.community.monsterv2 import extract_config

@pytest.mark.xfail(reason="todo")
def test_monsterv2():
    with open(
        "tests/data/malware/b842281e64924baa7c011501d7778075da412d66986e6aa65fd7d171cf074d70",
        "rb",
    ) as data:
        conf = extract_config(data.read())
        assert conf == {
            "raw": {
                "anti_dbg": False,
                "anti_sandbox": False,
                "aurotun": False,
                "build_name": "Se2",
                "disable_mutex": False,
                "ip": "162.33.177.183",
                "kx_pk": "gUpjAMXma3Kiq8lZx/2UY1kcKTlsy5CMf+/y2IuUg1A=",
                "port": 7712,
                "priviledge_escalation": True,
                "seal_pk": "J2urRTT6yFi+WosGLdpP8bSyxwOPg9PTYYDVEpCZhw0=",
                "sign_pk": "XkEb9v3B99RHP+k4LgFOvrq+WQPKPKHpIx4VKvw6IQc=",
            },
            "CNCs": ["tcp://162.33.177.183:7712"],
            "build": "Se2",
        }
