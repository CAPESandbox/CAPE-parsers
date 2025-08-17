import base64
import yara
import pefile
import json
import struct
import re


RULE_SOURCE_KEY = """
rule Amadey_Key_String
{
    meta:
        author = "YungBinary"
        description = "Find decryption key in Amadey."
    strings:
        $chunk_1 = { 
            6A 20
            68 ?? ?? ?? ??
            B9 ?? ?? ?? ??
            E8 ?? ?? ?? ??
            68 ?? ?? ?? ??
            E8 ?? ?? ?? ??
            59
            C3
        }
    condition:
        $chunk_1
}
"""

RULE_SOURCE_ENCODED_STRINGS = """
rule Amadey_Encoded_Strings
{
    meta:
        author = "YungBinary"
        description = "Find encoded strings in Amadey."
    strings:
        $chunk_1 = { 
            6A ??
            68 ?? ?? ?? ??
            B9 ?? ?? ?? ??
            E8 ?? ?? ?? ??
            68 ?? ?? ?? ??
            E8 ?? ?? ?? ??
            59
            C3
        }
    condition:
        $chunk_1
}
"""


def contains_non_printable(byte_array):
    for byte in byte_array:
        if not chr(byte).isprintable():
            return True
    return False


def yara_scan_generator(raw_data, rule_source):
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                yield instance.offset, block.identifier


def get_keys(pe, data):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    keys = []
    for offset, _ in yara_scan_generator(data, RULE_SOURCE_KEY):
        try:
            key_string_rva = struct.unpack('i', data[offset + 3 : offset + 7])[0]
            key_string_dword_offset = pe.get_offset_from_rva(key_string_rva - image_base)
            key_string = pe.get_string_from_data(key_string_dword_offset, data)
    
            if not b"=" in key_string:
                keys.append(key_string.decode())
            
            if len(keys) == 2:
                return keys

        except:
            continue
    
    return []


def get_encoded_strings(pe, data):
    encoded_strings = []
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for offset, _ in yara_scan_generator(data, RULE_SOURCE_ENCODED_STRINGS):

        try:
            encoded_string_size = data[offset + 1]
            encoded_string_rva = struct.unpack('i', data[offset + 3 : offset + 7])[0]
            encoded_string_dword_offset = pe.get_offset_from_rva(encoded_string_rva - image_base)
            encoded_string = pe.get_string_from_data(encoded_string_dword_offset, data)

            # Make sure the string matches length from operand
            if encoded_string_size != len(encoded_string):
                continue
            
            encoded_strings.append(encoded_string.decode())

        except:
            continue

    return encoded_strings


def decode_amadey_string(key: str, encoded_str: str) -> bytes:
    """
    Decode Amadey encoded strings that look like base64
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "

    decoded = ""
    for i in range(len(encoded_str)):
        if encoded_str[i] == "=":
            decoded += "="
            continue

        index_1 = alphabet.index(encoded_str[i % len(encoded_str)])
        index_2 = alphabet.index(key[i % len(key)])

        index_result = (index_1 + (0x3F - index_2) + 0x3F) % 0x3F
        
        decoded += alphabet[index_result]

    decoded = base64.b64decode(decoded)

    return decoded


def find_campaign_id(data):
    pattern = br'\x00\x00\x00([0-9a-f]{6})\x00\x00'
    matches = re.findall(pattern, data)
    if matches:
        return matches[0]


def extract_config(data):
    pe = pefile.PE(data=data, fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    keys = get_keys(pe, data)
    if not keys:
        return {}

    decode_key = keys[0]
    rc4_key = keys[1]
    encoded_strings = get_encoded_strings(pe, data)

    decoded_strings = []
    for encoded_string in encoded_strings:
        try:
            decoded_string = decode_amadey_string(decode_key, encoded_string)
            if not decoded_string or contains_non_printable(decoded_string):
                continue
            decoded_strings.append(decoded_string.decode())
        except:
            continue
    
    if not decoded_strings:
        return {}

    decoded_strings = decoded_strings[:10]
    final_config = {"C2": []}
    version = ""
    install_dir = ""
    install_file = ""
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    version_pattern = r"^\d+\.\d{1,2}$"
    install_dir_pattern = r"^[0-9a-f]{10}$"

    for i in range(len(decoded_strings)):
        if re.match(ip_pattern, decoded_strings[i]):
            final_config["C2"].append(f"http://" + decoded_strings[i] + decoded_strings[i+1])
        elif re.match(version_pattern, decoded_strings[i]):
            version = decoded_strings[i]
        elif re.match(install_dir_pattern, decoded_strings[i]):
            install_dir = decoded_strings[i]
        elif decoded_strings[i].endswith(".exe"):
            install_file = decoded_strings[i]

    if version:
        final_config["version"] = version
    if install_dir:
        final_config["install_dir"] = install_dir
    if install_file:
        final_config["install_file"] = install_file
    
    final_config["rc4_key"] = rc4_key

    campaign_id = find_campaign_id(data)
    if campaign_id:
        final_config["campaign_id"] = campaign_id.decode()

    return final_config



if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(json.dumps(extract_config(f.read()), indent=4))
