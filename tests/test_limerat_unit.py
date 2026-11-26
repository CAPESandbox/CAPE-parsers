import base64
import logging
import struct
from types import SimpleNamespace
from unittest.mock import patch

from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding

from cape_parsers.CAPE.community import LimeRAT


def _encrypt_config_url(plaintext: str, encryption_key: str) -> str:
    aes_key = LimeRAT._aes_key(encryption_key)
    ct = AES.new(aes_key, AES.MODE_ECB).encrypt(
        Padding.pad(plaintext.encode("utf-8"), block_size=AES.block_size, style="pkcs7")
    )
    return base64.b64encode(ct).decode("ascii")


def _build_cil_cctor(string_field_pairs: list[tuple[int, int]]) -> bytes:
    """Build a CIL fat method body: repeated (ldstr rid, stsfld field_rid) + ret."""
    code = bytearray()
    for str_rid, field_rid in string_field_pairs:
        code += b"\x72" + struct.pack("<I", 0x70000000 | str_rid)
        code += b"\x80" + struct.pack("<I", 0x04000000 | field_rid)
    code += b"\x2a"  # ret
    # Fat header (12 bytes): flags=0x3003 (size=3 dwords, CorILMethod_FatFormat), maxstack=8, codesize, localvarsigtok=0
    header = struct.pack("<HHII", 0x3003, 8, len(code), 0)
    return header + bytes(code)


def _make_fake_dnpe(method_bytes: bytes, user_strings: dict[int, str], field_names: list[str]):
    us_map = {rid: SimpleNamespace(value=val) for rid, val in user_strings.items()}

    class _FakeUS:
        def get(self, rid):
            return us_map.get(rid)

    field_rows = [SimpleNamespace(Name=SimpleNamespace(value=name)) for name in field_names]
    method_row = SimpleNamespace(
        Rva=0x2000,
        ImplFlags=SimpleNamespace(miIL=True),
        Flags=SimpleNamespace(mdAbstract=False, mdPinvokeImpl=False),
        Name=SimpleNamespace(value=".cctor"),
    )

    class _FakePE:
        def __init__(self):
            self.__data__ = b"\x00" * 0x100 + method_bytes
            self.net = SimpleNamespace(
                user_strings=_FakeUS(),
                mdtables=SimpleNamespace(
                    MethodDef=[method_row],
                    Field=SimpleNamespace(rows=field_rows),
                ),
            )

        def get_offset_from_rva(self, rva):
            return 0x100 if rva == 0x2000 else 0

        def close(self):
            pass

    return _FakePE()


def test_limerat_aes_key_and_url_helpers():
    assert LimeRAT._aes_key("NYANCAT").hex() == "4823ed16951e7debcf8570cf0d37774823ed16951e7debcf8570cf0d37775100"

    assert LimeRAT._format_cnc("https://pastebin.com/raw/abc") == "https://pastebin.com:443/raw/abc"
    assert LimeRAT._format_cnc("198.51.100.10:5600") == "tcp://198.51.100.10:5600"
    assert LimeRAT._format_cnc("[2001:db8::1]:4444") == "tcp://[2001:db8::1]:4444"
    assert LimeRAT._format_cnc("198.51.100.10:0") is None
    assert LimeRAT._format_cnc("198.51.100.10:99999") is None

    enc_bad_port = _encrypt_config_url("198.51.100.10:99999", "k")
    assert LimeRAT._decrypt_config_url(enc_bad_port, "k") is None


def test_limerat_null_mdtables_and_zero_rva_do_not_log_error(caplog):
    pe_no_tables = SimpleNamespace(
        net=SimpleNamespace(user_strings=SimpleNamespace(), mdtables=None),
        close=lambda: None,
    )
    with (
        patch("cape_parsers.CAPE.community.LimeRAT.dnfile.dnPE", return_value=pe_no_tables),
        caplog.at_level(logging.ERROR, logger=LimeRAT.__name__),
    ):
        assert LimeRAT.extract_config(b"MZ_fake") == {}
    assert "LimeRAT config extraction failed" not in caplog.text

    zero_rva_method = SimpleNamespace(
        Rva=0,
        ImplFlags=SimpleNamespace(miIL=True),
        Flags=SimpleNamespace(mdAbstract=False, mdPinvokeImpl=False),
        Name=SimpleNamespace(value=".cctor"),
    )
    pe_zero_rva = SimpleNamespace(
        __data__=b"MZ" + b"\x00" * 64,
        net=SimpleNamespace(
            user_strings=SimpleNamespace(get=lambda rid: None),
            mdtables=SimpleNamespace(MethodDef=[zero_rva_method]),
        ),
        get_offset_from_rva=lambda rva: (_ for _ in ()).throw(AssertionError("should not read RVA 0")),
        close=lambda: None,
    )
    with patch("cape_parsers.CAPE.community.LimeRAT.dnfile.dnPE", return_value=pe_zero_rva):
        assert LimeRAT.extract_config(b"MZ_fake") == {}


def test_limerat_anchored_extra_literals_in_cctor():
    enc_key = "NYANCAT"
    enc_url = _encrypt_config_url("https://pastebin.com/raw/LJe9sUk5", enc_key)
    # Extra leading and trailing literals around the 15-field LimeRAT block
    literals = [
        "extra_header_v0.1.9",
        enc_url,
        enc_key,
        "|'N'|",
        "|'L'|",
        "Wservices.exe",
        "True",
        "False",
        "False",
        "False",
        "Temp",
        "\\",
        "1B5aLZh6psoQttLGn9tpbdibiWqzyh4Jfv",
        "False",
        "",
        "3",
        "extra_mutex_tail",
    ]
    user_strings = {i + 1: val for i, val in enumerate(literals)}
    field_names = [f"f{i}" for i in range(len(literals))]
    cil_body = _build_cil_cctor([(i + 1, i + 1) for i in range(len(literals))])
    fake_pe = _make_fake_dnpe(cil_body, user_strings, field_names)

    with patch("cape_parsers.CAPE.community.LimeRAT.dnfile.dnPE", return_value=fake_pe):
        cfg = LimeRAT.extract_config(b"MZ_fake")

    assert cfg["cryptokey"] == LimeRAT._aes_key(enc_key).hex()
    assert cfg["cryptokey_type"] == "AES"
    assert cfg["CNCs"] == ["https://pastebin.com:443/raw/LJe9sUk5"]
    assert cfg["raw"]["config_url_type"] == "dead_drop"
    assert cfg["raw"]["exe"] == "Wservices.exe"
    assert cfg["raw"]["delay"] == 3


def test_limerat_named_stsfld_custom_delimiters_and_direct_cnc():
    enc_key = "customkey"
    enc_c2 = _encrypt_config_url("198.51.100.10:5600", enc_key)
    entries = [
        ("KEY", enc_key),
        ("Host", enc_c2),
        ("ENDOF", "|CUSTOM_END|"),
        ("SPL", "|CUSTOM_SPL|"),
        ("EXE", "client.exe"),
        ("Delay", "10"),
    ]
    user_strings = {i + 1: val for i, (_, val) in enumerate(entries)}
    field_names = [name for name, _ in entries]
    cil_body = _build_cil_cctor([(i + 1, i + 1) for i in range(len(entries))])
    fake_pe = _make_fake_dnpe(cil_body, user_strings, field_names)

    with patch("cape_parsers.CAPE.community.LimeRAT.dnfile.dnPE", return_value=fake_pe):
        cfg = LimeRAT.extract_config(b"MZ_fake")

    assert cfg["cryptokey"] == LimeRAT._aes_key(enc_key).hex()
    assert cfg["CNCs"] == ["tcp://198.51.100.10:5600"]
    assert cfg["raw"]["config_url"] == "198.51.100.10:5600"
    assert cfg["raw"]["config_url_type"] == "direct"
    assert cfg["raw"]["endof"] == "|CUSTOM_END|"
    assert cfg["raw"]["split"] == "|CUSTOM_SPL|"
    assert cfg["raw"]["exe"] == "client.exe"
    assert cfg["raw"]["delay"] == 10
