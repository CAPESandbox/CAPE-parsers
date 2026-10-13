from cape_parsers.CAPE.community import MonsterV2


def test_monsterv2_import_and_key_derivation():
    key, nonce = MonsterV2.derive_chacha_key_nonce_blake2b(b"A" * 32)
    assert len(key) == 32
    assert len(nonce) == 24
    assert MonsterV2.extract_config(b"not a pe") == {}
