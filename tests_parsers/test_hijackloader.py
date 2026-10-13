from cape_parsers.CAPE.community.HijackLoader import extract_config


def test_hijackloader():
    with open(
        "tests/data/malware/aded29b731b756ea3d81ca04034a4ec904468a17b9f9928dc2d32ed8e9c0c666",
        "rb",
    ) as data:
        conf = extract_config(data.read())
        assert conf == {
            "raw": {
                "directory": "%APPDATA%\\hostshell_32",
                "inject_dll": "%windir%\\SysWOW64\\rasapi32.dll",
                "exe_name": "Chime.exe",
            },
        }
