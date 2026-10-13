from unittest.mock import MagicMock, patch

from Cryptodome.Cipher import ARC4

from cape_parsers.CAPE.core import BumbleBee


def _make_fake_pe():
    pe = MagicMock()
    pe.get_rva_from_offset.side_effect = lambda off: off
    pe.get_offset_from_rva.side_effect = lambda rva: rva
    return pe


def test_extract_config_multi_key_non_utf8_and_empty_key_does_not_raise(caplog):
    # Two key_regex matches: first points to non-UTF-8 bytes (0xa0...), second points to empty null byte (b"\x00"),
    # followed by a config_match pattern. Should not raise UnicodeDecodeError or ValueError in ARC4.new.
    k1_ins = b"\x48\x8d\x05\x00\x00\x00\x00\x80\x3d\x00\x00\x00\x00\x00"
    k2_ins = b"\x48\x8d\x05\x00\x00\x00\x00\x80\x3d\x00\x00\x00\x00\x00"
    cfg_ins = (
        b"\x48\x8d\x05\x00\x00\x00\x00"
        b"\x48\x8d\x0d\x00\x00\x00\x00"
        b"\x48\x8d\x15\x00\x00\x00\x00"
    )
    data = k1_ins + k2_ins + cfg_ins + b"\x00" * 128

    fake_pe = _make_fake_pe()
    with (
        patch("cape_parsers.CAPE.core.BumbleBee.pefile.PE", return_value=fake_pe),
        patch("cape_parsers.CAPE.core.BumbleBee.extract_key_data", side_effect=[b"\xa0\x89test", b""]),
        patch("cape_parsers.CAPE.core.BumbleBee.extract_2024", return_value={}),
    ):
        cfg = BumbleBee.extract_config(data)

    assert "This is broken" not in caplog.text
    assert cfg == {"botnet": "\ufffd\ufffdtest"}


def test_extract_config_single_key_rc4_decryption():
    rc4_key = b"secretkey"
    k1_ins = b"\x48\x8d\x05\x00\x00\x00\x00\x80\x3d\x00\x00\x00\x00\x00"
    cfg_ins = (
        b"\x48\x8d\x05\x00\x00\x00\x00"
        b"\x48\x8d\x0d\x00\x00\x00\x00"
        b"\x48\x8d\x15\x00\x00\x00\x00"
    )
    data = k1_ins + cfg_ins

    camp_ct = ARC4.new(rc4_key).encrypt(b"camp1\x00")
    bot_ct = ARC4.new(rc4_key).encrypt(b"bot1\x00")
    c2_ct = ARC4.new(rc4_key).encrypt(b"1.2.3.4:443,5.6.7.8:443\x00")

    fake_pe = _make_fake_pe()
    with (
        patch("cape_parsers.CAPE.core.BumbleBee.pefile.PE", return_value=fake_pe),
        patch("cape_parsers.CAPE.core.BumbleBee.extract_key_data", return_value=rc4_key),
        patch("cape_parsers.CAPE.core.BumbleBee.extract_config_data", return_value=(camp_ct, bot_ct, c2_ct)),
    ):
        cfg = BumbleBee.extract_config(data)

    assert cfg == {
        "cryptokey": "secretkey",
        "cryptokey_type": "RC4",
        "campaign": "camp1",
        "botnet": "bot1",
        "CNCs": ["1.2.3.4:443", "5.6.7.8:443"],
    }
