import logging
import struct
from contextlib import suppress

from Cryptodome.Cipher import ARC4

from cape_parsers.utils import yara_wrapper as yara

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

rule_source = """
rule SmokeLoader
{
    meta:
        author = "kevoreilly"
        description = "SmokeLoader Config Extraction"
    strings:
        $fetch_c2_64_1 = {74 ?? B? E8 03 00 00 B9 58 02 00 00 FF [5] 48 (FF C?|83 EF 01) 75 (F0|EF) [6-10] 48 8D 05}
        $fetch_c2_64_2 = {74 ?? B? E8 03 00 00 B9 58 02 00 00 FF [5] 48 (FF C?|83 EF 01) 75 (F0|EF) 33 C9 E8}
        $fetch_c2_32 = {8B 96 [2] (00|01) 00 8B CE 5E 8B 14 95 [4] E9}
    condition:
        any of them
}
"""

yara_rules = yara.compile(source=rule_source)


def rc4_decrypt(key, ciphertext):
    ARC4.key_size = range(1, 257)
    arc4 = ARC4.new(key)
    return arc4.decrypt(ciphertext)


def swap32(x):
    return int.from_bytes(x.to_bytes(4, byteorder="little"), byteorder="big", signed=False)


def decode(buffer):
    string = ""
    length = buffer[0]
    key = swap32(struct.unpack("<I", buffer[length + 1 : length + 1 + 4])[0])
    for i in buffer[1 : length + 1]:
        x = i ^ (key & 0xFF)
        key = key >> 8
        x = x ^ (key & 0xFF)
        key = key >> 8
        x = x ^ (key & 0xFF)
        key = key >> 8
        x = -(x ^ (key & 0xFF) - (1 << 8)) & 0xFF
        string += chr(x - 1)
        key = swap32(struct.unpack("<I", buffer[length + 1 : length + 1 + 4])[0])
    return string


def extract_config(filebuf):
    cfg = {}
    c2list = []
    c2list_offset = 0
    matches = yara_rules.match(data=filebuf)
    if not matches:
        return
    for match in matches:
        if match.rule != "SmokeLoader":
            continue
        for item in match.strings:
            for instance in item.instances:
                if "$fetch_c2_64_1" in item.identifier:
                    match_offset = (int(instance.offset) & 0xFFFF) + instance.matched_length
                    try:
                        c2list_offset = (
                            struct.unpack("<I", filebuf[match_offset : match_offset + 4])[0] + match_offset + 4
                        ) & 0xFFFF
                    except Exception:
                        break
                    delta = 8
                if "$fetch_c2_64_2" in item.identifier:
                    match_offset = (int(instance.offset) & 0xFFFF) + instance.matched_length
                    try:
                        func = (
                            struct.unpack("<I", filebuf[match_offset : match_offset + 4])[0] + match_offset + 4
                        ) & 0xFFFF
                        c2list_pointer = struct.unpack("i", filebuf[func+11:func+15])[0]+func+15
                        c2list_offset = struct.unpack("H", filebuf[c2list_pointer:c2list_pointer+2])[0]
                    except Exception:
                        break
                    delta = 8
                if "$fetch_c2_32" in item.identifier:
                    match_offset = (int(instance.offset) & 0xFFFF) + 12
                    try:
                        c2list_offset = (struct.unpack("<I", filebuf[match_offset : match_offset + 4])[0]) & 0xFFFF
                    except Exception:
                        break
                    delta = 4
    if not c2list_offset:
        return
    while c2list_offset:
        with suppress(Exception):
            c2_offset = struct.unpack("<H", filebuf[c2list_offset : c2list_offset + 2])[0]
            line = filebuf[c2_offset:]
            size = struct.unpack("B", line[0:1])[0]
            if size and size < 100:
                c2 = decode(line)
                if c2.startswith("http"):
                    c2list.append(c2)
                else:
                    c2 = rc4_decrypt(line[1:5], line[5 : size + 5]).decode()
                    if c2.startswith("http"):
                        c2list.append(c2)
        if not c2_offset or c2_offset < 0x100:
            break
        c2list_offset += delta
    if c2list != []:
        cfg["CNCs"] = sorted(list(set(c2list)))
    return cfg


if __name__ == "__main__":
    import sys
    from pathlib import Path

    logging.basicConfig()
    log.setLevel(logging.DEBUG)
    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
