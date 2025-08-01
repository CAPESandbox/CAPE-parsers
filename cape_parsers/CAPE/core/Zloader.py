# Copyright (C) 2020 Kevin O'Reilly (kevoreilly@gmail.com)
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

DESCRIPTION = "Zloader configuration parser"
AUTHOR = "kevoreilly"

import logging
import socket
import struct

import pefile
from Cryptodome.Cipher import ARC4

import yara

log = logging.getLogger(__name__)

rule_source = """
rule Zloader
{
    meta:
        author = "kevoreilly, enzok"
        description = "Zloader Payload"
        cape_type = "Zloader Payload"
    strings:
        $rc4_init = {31 [1-3] 66 C7 8? 00 01 00 00 00 00 90 90 [0-5] 8? [5-90] 00 01 00 00 [0-15] (74|75)}
        $decrypt_conf = {e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 08 e8 ?? ?? ?? ??}
        $decrypt_conf_1 = {48 8d [5] [0-6] e8 [4] 48 [3-4] 48 [3-4] 48 [6] E8}
        $decrypt_conf_2 = {48 8d [5] 4? [5] e8 [4] 48 [3-4] 48 8d [5] E8 [4] 48}
        $decrypt_key_1 = {66 89 C2 4? 8D 0D [3] 00 4? B? FC 03 00 00 E8 [4] 4? 83 C4}
        $decrypt_key_2 = {48 8d 0d [3] 00 66 89 ?? 4? 89 F0 4? [2-5] E8 [4-5] 4? 83 C4}
        $decrypt_key_3 = {48 8d 0d [3] 00 e8 [4] 66 89 [3] b? [4] e8 [4] 66 8b}
    condition:
        uint16(0) == 0x5A4D and 1 of ($decrypt_conf*) and (1 of ($decrypt_key*) or $rc4_init)
}

rule Zloader2024
{
    meta:
        author = "enzok"
        description = "Zloader Payload"
        cape_type = "Zloader Payload"
    strings:
        $conf_1 = {48 01 ?? 48 8D 15 [4] 41 B8 ?? 04 00 00 E8 [4] [0-5] C7 [1-2] 00 00 00 00}
        $confkey_1 = {48 8D 15 [4] 48 89 ?? 49 89 ?? E8 [4] [0-5] C7 [1-2] 00 00 00 00}
        $confkey_2 = {48 01 ?? 48 8D 15 [4] 41 B8 10 00 00 00 E8 [4] [0-5] C7 [1-2] 00 00 00 00 (48 8B|8B)}
        $confkey_3 = {48 01 ?? 48 8D 15 [4] 41 B8 10 00 00 00 E8 [4] [0-5] C7 [1-2] 00 00 00 00 48 83 C4}
    condition:
        uint16(0) == 0x5A4D and $conf_1 and 2 of ($confkey_*)
}
"""
MAX_STRING_SIZE = 32

yara_rules = yara.compile(source=rule_source)


def decrypt_rc4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


def string_from_offset(data, offset):
    return data[offset : offset + MAX_STRING_SIZE].split(b"\0", 1)[0]


def parse_config(data):
    parsed = {}
    parsed["botnet"] = data[4:].split(b"\x00", 1)[0].decode("utf-8")
    parsed["campaign"] = data[25:].split(b"\x00", 1)[0].decode("utf-8")
    c2s = []
    c2_data = data[46:686]
    for i in range(10):
        chunk = c2_data[i * 64 : (i + 1) * 64]
        chunk = chunk.rstrip(b"\x00")
        if chunk:
            c2s.append(chunk.decode("utf-8"))
    parsed["CNCs"] = c2s
    parsed["cryptokey"] = data[704:].split(b"\x00", 1)[0]
    parsed["cryptokey_type"] = "RSA Public Key"
    dns_data = data[1004:].split(b"\x00", 1)[0]
    parsed["TLS SNI"] = dns_data.split(b"~")[0].decode("utf-8").rstrip()
    parsed["DNS C2"] = dns_data.split(b"~")[1].decode("utf-8").strip()
    dns_ips = []
    dns_ips.append(socket.inet_ntoa(data[1204:1208].split(b"\x00", 1)[0]))
    dns_ip_data = data[1208:1248]
    for i in range(10):
        chunk = dns_ip_data[i * 4 : (i + 1) * 4]
        chunk = chunk.rstrip(b"\x00")
        if chunk:
            dns_ips.append(socket.inet_ntoa(chunk))
    parsed["DNS Servers"] = dns_ips
    return parsed


def extract_config(filebuf):
    config = {}
    end_config = {}
    pe = pefile.PE(data=filebuf, fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    matches = yara_rules.match(data=filebuf)
    if not matches:
        return
    conf_type = ""
    decrypt_key = ""
    conf_size = 1020
    for match in matches:
        if match.rule == "Zloader":
            for item in match.strings:
                if "$decrypt_conf" == item.identifier:
                    decrypt_conf = item.instances[0].offset + 21
                    conf_type = "1"
                elif "$decrypt_conf_1" == item.identifier:
                    decrypt_conf = item.instances[0].offset
                    cva = 3
                    conf_type = "2"
                elif "$decrypt_conf_2" == item.identifier:
                    decrypt_conf = item.instances[0].offset
                    cva = 3
                    conf_type = "2"
                elif "$decrypt_key_1" == item.identifier:
                    decrypt_key = item.instances[0].offset
                    kva_s = 6
                elif "$decrypt_key_2" == item.identifier:
                    decrypt_key = item.instances[0].offset
                    kva_s = 3
                elif "$decrypt_key_3" == item.identifier:
                    decrypt_key = item.instances[0].offset
                    kva_s = 3
        elif match.rule == "Zloader2024":
            conf_size = 1264
            rc4_chunk1 = None
            rc4_chunk2 = None
            numchunks = 0
            for item in match.strings:
                if "$conf_1" == item.identifier:
                    decrypt_conf = item.instances[0].offset + 6
                    conf_size = item.instances[0].offset + 12
                    conf_type = "3"
                elif item.identifier.startswith("$confkey_") and numchunks < 2:
                    matched_data = item.instances[0].matched_data[:2]
                    if matched_data == b"\x48\x8D":
                        offset = 3
                    elif matched_data == b"\x48\x01":
                        offset = 6

                    chunk_offset = item.instances[0].offset + offset
                    if not rc4_chunk1:
                        rc4_chunk1 = chunk_offset
                    elif not rc4_chunk2:
                        rc4_chunk2 = chunk_offset

                    numchunks += 1

    if conf_type == "1":
        va = struct.unpack("I", filebuf[decrypt_conf : decrypt_conf + 4])[0]
        key = string_from_offset(filebuf, pe.get_offset_from_rva(va - image_base))
        data_offset = pe.get_offset_from_rva(struct.unpack("I", filebuf[decrypt_conf + 5 : decrypt_conf + 9])[0] - image_base)
        enc_data = filebuf[data_offset:].split(b"\0\0", 1)[0]
        raw = decrypt_rc4(key, enc_data)
        items = list(filter(None, raw.split(b"\x00\x00")))
        config["botnet"] = items[1].lstrip(b"\x00")
        config["campaign"] = items[2]
        for item in items:
            item = item.lstrip(b"\x00")
            if item.startswith(b"http"):
                config.setdefault("CNCs", []).append(item)
            elif len(item) == 16:
                config["cryptokey"] = item
                config["cryptokey_type"] = "RC4"
    elif conf_type == "2" and decrypt_key:
        conf_va = struct.unpack("I", filebuf[decrypt_conf + cva : decrypt_conf + cva + 4])[0]
        conf_offset = pe.get_offset_from_rva(conf_va + pe.get_rva_from_offset(decrypt_conf) + cva + 4)
        # if not conf_size:
        # conf_size = struct.unpack("I", filebuf[decrypt_key + size_s : decrypt_key + size_s + 4])[0]
        key_va = struct.unpack("I", filebuf[decrypt_key + kva_s : decrypt_key + kva_s + 4])[0]
        key_offset = pe.get_offset_from_rva(key_va + pe.get_rva_from_offset(decrypt_key) + kva_s + 4)
        key = string_from_offset(filebuf, key_offset)
        conf_data = filebuf[conf_offset : conf_offset + conf_size]
        raw = decrypt_rc4(key, conf_data)
        items = list(filter(None, raw.split(b"\x00\x00")))
        config["botnet"] = items[0].decode("utf-8")
        config["campaign"] = items[1].decode("utf-8")
        for item in items:
            item = item.lstrip(b"\x00")
            if item.startswith(b"http"):
                config.setdefault("CNCs", []).append(item.decode("utf-8"))
            elif b"PUBLIC KEY" in item:
                config["cryptokey"] = item.decode("utf-8").replace("\n", "")
                config["cryptokey_type"] = "RSA Public key"
    elif conf_type == "3" and rc4_chunk1 and rc4_chunk2:
        conf_va = struct.unpack("I", filebuf[decrypt_conf : decrypt_conf + 4])[0]
        conf_offset = pe.get_offset_from_rva(conf_va + pe.get_rva_from_offset(decrypt_conf) + 4)
        conf_data = filebuf[conf_offset : conf_offset + conf_size]
        keychunk1_va = struct.unpack("I", filebuf[rc4_chunk1 : rc4_chunk1 + 4])[0]
        keychunk1_offset = pe.get_offset_from_rva(keychunk1_va + pe.get_rva_from_offset(rc4_chunk1) + 4)
        keychunk1 = filebuf[keychunk1_offset : keychunk1_offset + 16]
        keychunk2_va = struct.unpack("I", filebuf[rc4_chunk2 : rc4_chunk2 + 4])[0]
        keychunk2_offset = pe.get_offset_from_rva(keychunk2_va + pe.get_rva_from_offset(rc4_chunk2) + 4)
        keychunk2 = filebuf[keychunk2_offset : keychunk2_offset + 16]
        decrypt_key = bytes(a ^ b for a, b in zip(keychunk1, keychunk2))
        conf = decrypt_rc4(decrypt_key, conf_data)
        end_config = parse_config(conf)

    if config and end_config:
        config = config.update({"raw": end_config})

    return config

if __name__ == "__main__":
    import sys
    from pathlib import Path

    log.setLevel(logging.DEBUG)
    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
