"""
Description: MyKings AKA Smominru config parser
Author: x.com/YungBinary
"""

from contextlib import suppress
import json
import re
import base64


def contains_non_printable(byte_array):
    for byte in byte_array:
        if not chr(byte).isprintable():
            return True
    return False


def extract_base64_strings(data: bytes, minchars: int, maxchars: int) -> list:
    pattern = b"([A-Za-z0-9+/=]{" + str(minchars).encode() + b"," + str(maxchars).encode() + b"})\x00{4}"
    strings = []
    for string in re.findall(pattern, data):
        decoded_string = base64_and_printable(string.decode())
        if decoded_string:
            strings.append(decoded_string)
    return strings


def base64_and_printable(b64_string: str):
    with suppress(Exception):
        decoded_bytes = base64.b64decode(b64_string)
        if not contains_non_printable(decoded_bytes):
            return decoded_bytes.decode('ascii')


def extract_config(data: bytes) -> dict:
    config_dict = {}
    with suppress(Exception):
        cncs = extract_base64_strings(data, 12, 60)
        if cncs:
            # as they don't have schema they going under raw
            config_dict["raw"] = {"CNCs": cncs}
            return config_dict

    return {}


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(json.dumps(extract_config(f.read()), indent=4))
