import itertools

from cape_parsers.CAPE.community import Vidar


def _xor_encode(plaintext: bytes, key: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(plaintext, itertools.cycle(key)))


def _build_vidar_blob(key: bytes, version: bytes, build_id: bytes, records: list[tuple[bytes, bytes, bytes]]) -> bytes:
    total_len = Vidar.RECS + Vidar.REC_STRIDE * max(1, len(records))
    blob = bytearray(total_len)
    blob[0 : Vidar.KEYLEN] = key

    enc_ver = _xor_encode(version, key)
    blob[Vidar.VER_OFF : Vidar.VER_OFF + len(enc_ver)] = enc_ver
    blob[Vidar.VER_LEN] = len(version)

    enc_bid = _xor_encode(build_id, key)
    blob[Vidar.BID_OFF : Vidar.BID_OFF + len(enc_bid)] = enc_bid
    blob[Vidar.BID_LEN] = len(build_id)

    for idx, (url, tag, ua) in enumerate(records):
        base = Vidar.RECS + Vidar.REC_STRIDE * idx
        enc_url = _xor_encode(url, key)
        blob[base + Vidar.URL_OFF : base + Vidar.URL_OFF + len(enc_url)] = enc_url
        blob[base + Vidar.URL_LEN] = len(url)

        enc_tag = _xor_encode(tag, key)
        blob[base + Vidar.TAG_OFF : base + Vidar.TAG_OFF + len(enc_tag)] = enc_tag
        blob[base + Vidar.TAG_LEN] = len(tag)

        enc_ua = _xor_encode(ua, key)
        blob[base + Vidar.UA_OFF : base + Vidar.UA_OFF + len(enc_ua)] = enc_ua
        blob[base + Vidar.UA_LEN] = len(ua)

    return bytes(blob)


def test_vidar_extract_config_short_and_empty():
    assert Vidar.extract_config(b"") is None
    assert Vidar.extract_config(b"\x00" * 512) is None


def test_vidar_extract_config_multi_record():
    key = bytes(range(0x11, 0x21))
    blob = _build_vidar_blob(
        key=key,
        version=b"1.8",
        build_id=b"camp42",
        records=[
            (b"http://198.51.100.10/gate", b"tag1", b"Mozilla/5.0"),
            (b"https://example.invalid/c2", b"tag2", b"VidarUA"),
        ],
    )
    payload = b"\x00" * 128 + blob + b"\x00" * 64
    cfg = Vidar.extract_config(payload)
    assert cfg == {
        "version": "1.8",
        "build_id": "camp42",
        "cncs": ["http://198.51.100.10/gate", "https://example.invalid/c2"],
        "tags": ["tag1", "tag2"],
        "user_agents": ["Mozilla/5.0", "VidarUA"],
    }


def test_vidar_extract_config_across_chunk_boundary():
    key = bytes(range(0xA0, 0xB0))
    blob = _build_vidar_blob(
        key=key,
        version=b"1.7",
        build_id=b"chunked",
        records=[(b"http://203.0.113.5/api", b"t", b"ua")],
    )
    # Place blob start 2 bytes before the 1 MiB chunk boundary so "http" spans chunks.
    prefix_len = (1 << 20) - 2
    payload = b"\x00" * prefix_len + blob + b"\x00" * 16
    cfg = Vidar.extract_config(payload)
    assert cfg is not None
    assert cfg["version"] == "1.7"
    assert cfg["build_id"] == "chunked"
    assert cfg["cncs"] == ["http://203.0.113.5/api"]
