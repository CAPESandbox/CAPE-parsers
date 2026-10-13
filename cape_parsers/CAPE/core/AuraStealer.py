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
    aes_key, iv, dword1, dword2 = struct.unpack_from(HEADER_FORMAT, data, 0)
    ciphertext_size = dword1 ^ dword2
    cipher_data = data[HEADER_SIZE: HEADER_SIZE + ciphertext_size]
    return aes_key, iv, cipher_data


def decrypt(data: bytes) -> Tuple[bytes, bytes, bytes]:
    aes_key, iv, cipher_data = parse_blob(data)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(cipher_data)
    return aes_key, iv, unpad(plaintext_padded, AES.block_size)


def extract_config(data: bytes) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    plaintext = b""

    try:
        pe = pefile.PE(data=data, fast_load=True)
        data_sections = [s for s in pe.sections if b".data" in s.Name]
        if data_sections:
            scan_data = data_sections[0].get_data()
        else:
            scan_data = data
    except Exception:
        # Fallback to full buffer scan for raw memory dumps
        scan_data = data

    header_size = 56
    min_cipher_size = 100
    max_cipher_size = 50000

    for offset in range(len(scan_data) - header_size):
        dword1, dword2 = struct.unpack_from("<II", scan_data, offset + 48)
        cipher_size = dword1 ^ dword2

        # Fast validation: Check bounds and ensure AES block alignment
        if min_cipher_size <= cipher_size <= max_cipher_size and cipher_size % 16 == 0:
            if offset + header_size + cipher_size <= len(scan_data):
                exact_blob = scan_data[offset: offset + header_size + cipher_size]

                with suppress(Exception):
                    aes_key, iv, ptext = decrypt(exact_blob)
                    if ptext and b"conf" in ptext:
                        plaintext = ptext
                        break

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
