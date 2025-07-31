# Copyright (C) 2024 enzok
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import logging
import re
from contextlib import suppress

import pefile
import yara
from Cryptodome.Cipher import AES
from Cryptodome.Cipher.AES import MODE_CTR
from Cryptodome.Util import Counter

log = logging.getLogger(__name__)

DESCRIPTION = "Latrodectus configuration parser."
AUTHOR = "enzok"

yara_rule = """
rule Latrodectus
{
    meta:
        author = "enzok"
        description = "Latrodectus Payload"
        cape_type = "Latrodectus Payload"
        hash = "a547cff9991a713535e5c128a0711ca68acf9298cc2220c4ea0685d580f36811"
    strings:
        $fnvhash1 = {C7 04 24 C5 9D 1C 81 48 8B 44 24 20 48 89 44 24 08}
        $fnvhash2 = {8B 0C 24 33 C8 8B C1 89 04 24 69 04 24 93 01 00 01}
        $procchk1 = {E8 [3] FF 85 C0 74 [2] FF FF FF FF E9 [4] E8 [4] 89 44 24 ?? E8 [4] 83 F8 4B 73 ?? 83 [3] 06}
        $procchk2 = {72 [2] FF FF FF FF E9 [4] E8 [4] 83 F8 32 73 ?? 83 [3] 06}
		$version = {C7 44 2? ?? ?? 00 00 00 C7 44 2? ?? ?? 00 00 00 8B 05 [4] 89}
    condition:
        all of them
}

rule Latrodectus_AES
{
    meta:
        author = "enzok"
        description = "Latrodectus Payload"
        cape_type = "Latrodectus Payload"
        hash = "5cecb26a3f33c24b92a0c8f6f5175da0664b21d7c4216a41694e4a4cad233ca8"
    strings:
		$fnvhash1 = {C7 04 24 C5 9D 1C 81 48 8B 44 24 20 48 89 44 24 08}
        $fnvhash2 = {8B 0C 24 33 C8 8B C1 89 04 24 69 04 24 93 01 00 01}
		$key =  {C6 44 2? ?? ?? [150] C6 44 2? ?? ?? B8 02}
		$aes_ctr_1 = {8B 44 24 ?? FF C8 89 44 24 ?? 83 7C 24 ?? 00 7C ?? 4? 63 44 24 ?? 4? 8B 4C 24 ?? 0F B6 84 01 F0 00 00 00 3D FF 00 00 00}
		$aes_ctr_2 = {48 03 C8 48 8B C1 0F B6 ?? 48 63 4C 24 ?? 0F B6 4C 0C ?? 33 C1 48 8B 4C 24 ?? 48 8B 54 24 ?? 48 03 D1 48 8B CA 88 01}
		$version = {C7 44 2? ?? ?? 00 00 00 C7 44 2? ?? ?? 00 00 00 8B 05 [4] 89}
    condition:
        all of them
}
"""
yara_rules = yara.compile(source=yara_rule)


def yara_scan(raw_data):
    try:
        return yara_rules.match(data=raw_data)
    except Exception as e:
        print(e)


def decrypt_string_aes(data: bytes, key: bytes) -> bytes:
    len_data = int.from_bytes(data[:2], "little")
    iv = data[2:18]
    data = data[18 : 18 + len_data]
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    cipher = AES.new(key, mode=MODE_CTR, counter=ctr)
    return cipher.decrypt(data)


def prng_seed(seed):
    sub_expr = (seed + 11865) << 31 | (seed + 11865) >> 1
    expr1 = (sub_expr << 31 | sub_expr >> 1) << 30 & (2**64 - 1)
    sub_expr = (expr1 & 0xFFFFFFFF) | (expr1 >> 32)
    expr2 = ((sub_expr ^ 0x151D) >> 30) | (4 * (sub_expr ^ 0x151D)) & (2**32 - 1)
    return ((expr2 >> 31) | (2 * expr2)) & 0xFFFFFFFF


def decrypt_string(data, type):
    seed = int.from_bytes(data[:4], "little") & 0xFFFFFFFF
    length = (int.from_bytes(data[4:6], "little")) ^ (int.from_bytes(data[:2], "little")) & 0xFFFF
    src = data[6:]
    result = bytearray()

    for i in range(length):
        if type == 1:
            seed += 1
        elif type == 2:
            seed = prng_seed(seed)
        result.append((seed ^ src[i]) & 0xFF)
    return result


def get_aes_string(data, key):
    str_val = ""
    with suppress(Exception):
        str_val = decrypt_string_aes(data, key).decode("ascii").replace("\00", "")
    return str_val


def get_string(match, data):
    str_val = ""
    i = match.start() // 2
    with suppress(Exception):
        str_val = decrypt_string(data[i:], 1).decode("ascii").replace("\00", "")

    if not str_val:
        with suppress(Exception):
            str_val = decrypt_string(data[i:], 2).decode("ascii").replace("\00", "")

    return str_val


def fnv_hash(data):
    decode = 0x811C9DC5
    for key in data:
        decode = 0x1000193 * (decode ^ key) & 0xFFFFFFFF
    return decode


def extract_config(filebuf):
    yara_hit = yara_scan(filebuf)
    cfg = {}

    for hit in yara_hit:
        rule = hit.rule
        if "Latrodectus" in rule:
            version = ""
            is_aes = False
            key = ""
            if "AES" in rule:
                is_aes = True

            for item in hit.strings:
                for instance in item.instances:
                    if "$version" in item.identifier and not version:
                        data = instance.matched_data[::-1]
                        major = int.from_bytes(data[10:11], byteorder="big")
                        minor = int.from_bytes(data[18:19], byteorder="big")
                        version = f"{major}.{minor}"
                    if "$key" in item.identifier:
                        key = instance.matched_data[4::5]
            try:
                pe = pefile.PE(data=filebuf, fast_load=True)
                data_sections = [s for s in pe.sections if s.Name.find(b".data") != -1]
                if not data_sections:
                    return
                data = data_sections[0].get_data()
                str_vals = []
                c2 = []
                campaign = ""
                rc4_key = ""

                if is_aes and key:
                    for i in range(len(data)):
                        str_val = get_aes_string(data[i : i + 512], key)
                        if str_val and len(str_val) > 2:
                            str_vals.append(str_val)
                else:
                    hex_pattern = "".join([rf"{byte:02X}" for byte in data[:4]])
                    regex = re.compile(hex_pattern.lower())
                    matches = regex.finditer(data.hex())

                    for match in matches:
                        str_val = get_string(match, data)
                        if str_val and len(str_val) > 2:
                            str_vals.append(str_val)

                for i in range(len(str_vals) - 1):
                    val = str_vals[i]
                    if "/files/" in val:
                        offset = 1
                        if is_aes:
                            offset += 1
                        campaign = str_vals[i + offset]
                    elif "ERROR" in val:
                        rc4_key = str_vals[i + 1]
                    elif "http" in val:
                        c2.append(val)

                for item in c2:
                    str_vals.remove(item)

                cfg = {
                    "CNCs": c2,
                    "campaign": fnv_hash(campaign.encode()),
                    "version": version,
                    "cryptokey": rc4_key,
                    "cryptokey_type": "RC4",
                    "raw": {
                        "Strings": str_vals,
                        "Group name": campaign,
                    },
                }
            except Exception as e:
                log.error("Error: %s", e)

        if not cfg.get("C2", False) and not cfg.get("raw", {}).get("Group name", False):
            cfg = None
    return cfg


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
