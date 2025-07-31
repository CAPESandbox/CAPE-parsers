import logging
import struct
from contextlib import suppress

import pefile
from Cryptodome.Cipher import ARC4

log = logging.getLogger(__name__)

DESCRIPTION = "Adaptix beacon configuration parser."
AUTHOR = "enzok"


def parse_http_config(rc4_key: bytes, data: bytes) -> dict:
    config = {}
    offset = 0
    servers = []
    ports = []

    def read(fmt: str):
        nonlocal offset
        size = struct.calcsize(fmt)
        value = struct.unpack_from(fmt, data, offset)
        offset += size
        return value if len(value) > 1 else value[0]

    def read_str(length: int):
        nonlocal offset
        value = data[offset : offset + length].decode("utf-8", errors="replace")
        offset += length
        return value

    config["cryptokey"] = rc4_key.hex()
    config["cryptokey_type"] = "RC4"
    config["agent_type"] = f"{read('<I'):8X}"
    config["use_ssl"] = read("<B")
    host_count = read("<I")
    for host in range(host_count):
        host_length = read("<I")
        servers.append(read_str(host_length).strip("\x00"))
        ports.append(read("<I"))

    config["servers"] = servers
    config["ports"] = ports
    method_length = read("<I")
    config["http_method"] = read_str(method_length).strip("\x00")
    uri_length = read("<I")
    config["uri"] = read_str(uri_length).strip("\x00")
    parameter_length = read("<I")
    config["parameter"] = read_str(parameter_length).strip("\x00")
    useragent_length = read("<I")
    config["user_agent"] = read_str(useragent_length).strip("\x00")
    headers_length = read("<I")
    config["http_headers"] = read_str(headers_length).strip("\x00")
    config["ans_pre_size"] = read("<I")
    config["ans_size"] = read("<I")
    config["kill_date"] = read("<I")
    config["working_time"] = read("<I")
    config["sleep_delay"] = read("<I")
    config["jitter_delay"] = read("<I")

    return {"raw": config}


def extract_config(filebuf: bytes) -> dict:
    pe = pefile.PE(data=filebuf, fast_load=True)
    data_sections = [s for s in pe.sections if b".rdata" in s.Name]
    if not data_sections:
        return

    data = data_sections[0].get_data()
    data_len = len(data)
    pos = 0
    while pos + 4 <= data_len:
        start_offset = pos
        key_offset = struct.unpack_from("<I", data, pos)[0]
        pos += 4

        if pos + key_offset + 32 > data_len:
            pos = start_offset + 1
            continue

        encrypted_data = data[pos : pos + key_offset]
        pos += key_offset
        rc4_key = data[pos : pos + 16]

        if key_offset == 787:
            pass

        with suppress(Exception):
            decrypted = ARC4.new(rc4_key).decrypt(encrypted_data)
            if b"User-Agent" in decrypted:
                return parse_http_config(rc4_key, decrypted)

        pos = start_offset + 1

    return None


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
