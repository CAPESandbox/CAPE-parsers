import json
import struct
from contextlib import suppress
from typing import Any, Dict, Tuple

import pefile
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

# Define the format for the fixed-size header part.
# <   : little-endian
# 32s : 32-byte string (for aes_key)
# 16s : 16-byte string (for iv)
# I   : 4-byte unsigned int (for dword1)
# I   : 4-byte unsigned int (for dword2)
HEADER_FORMAT = "<32s16sII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # This will be 32 + 16 + 4 + 4 = 56 bytes

def parse_blob(data: bytes):
    """
    Parse the blob according to the scheme:
      - 32 bytes = AES key
      - Next 16 bytes = IV
      - Next 2 DWORDs (8 bytes total) = XOR to get cipher data size
      - Remaining bytes = cipher data of that size
    """
    aes_key, iv, dword1, dword2 = struct.unpack_from(header_format, config_blob, 0)
    cipher_size = dword1 ^ dword2
    cipher_data = data[HEADER_SIZE : HEADER_SIZE + ciphertet_size]
    return aes_key, iv, cipher_data


def decrypt(data: bytes) -> Tuple[bytes, bytes, bytes]:
    aes_key, iv, cipher_data = parse_blob(data)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(cipher_data)
    return aes_key, iv, unpad(plaintext_padded, AES.block_size)


def extract_config(data: bytes) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    plaintext = b""

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
        try:
            parsed = json.loads(plaintext.decode("utf-8", errors="ignore").rstrip("\x00"))
        except json.JSONDecodeError:
            return cfg

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
