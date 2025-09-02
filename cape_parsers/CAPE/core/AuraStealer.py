import json
import struct
from contextlib import suppress
from typing import Any, Dict, Tuple

import pefile
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad


def parse_blob(data: bytes):
    """
    Parse the blob according to the scheme:
      - 32 bytes = AES key
      - Next 16 bytes = IV
      - Next 2 DWORDs (8 bytes total) = XOR to get cipher data size
      - Remaining bytes = cipher data of that size
    """
    offset = 0
    aes_key = data[offset:offset + 32]
    offset += 32
    iv = data[offset:offset + 16]
    offset += 16
    dword1, dword2 = struct.unpack_from("<II", data, offset)
    cipher_size = dword1 ^ dword2
    offset += 8
    cipher_data = data[offset:offset + cipher_size]
    return aes_key, iv, cipher_data


def decrypt(data: bytes) -> Tuple[bytes, bytes, bytes]:
    aes_key, iv, cipher_data = parse_blob(data)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(cipher_data)
    return aes_key, iv, unpad(plaintext_padded, AES.block_size)


def extract_config(data: bytes) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    plaintext = ""
    pe = pefile.PE(data=data, fast_load=True)
    try:
        data_section = [s for s in pe.sections if s.Name.find(b".data") != -1][0]
    except IndexError:
        return cfg

    if not data_section:
        return cfg

    data = data_section.get_data()
    block_size = 4096
    zeros = b"\x00" * block_size
    offset = data.find(zeros)
    if offset == -1:
        return cfg

    while offset > 0:
        with suppress(Exception):
            aes_key, iv, plaintext = decrypt(data[offset : offset + block_size])
            if plaintext and b"conf" in plaintext:
                break

        offset -= 1

    if plaintext:
        parsed = json.loads(plaintext.decode("utf-8", errors="ignore").rstrip("\x00"))
        conf = parsed.get("conf", {})
        build = parsed.get("build", {})
        if conf:
            cfg = {
                "CNCs": conf.get("hosts"),
                "user_agent": conf.get("useragents"),
                "version": build.get("ver"),
                "build": build.get("build_id"),
                "cryptokey": aes_key.hex(),
                "cryptokey_type": "AES",
                "raw": {
                    "iv": iv.hex(),
                    "anti_vm": conf.get("anti_vm"),
                    "anti_dbg": conf.get("anti_dbg"),
                    "self_del": conf.get("self_del"),
                    "run_delay": conf.get("run_delay"),
                }
            }

    return cfg


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
