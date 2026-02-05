import struct
import pefile
import yara
import ipaddress
from contextlib import suppress


# V1 hash = 619751f5ed0a9716318092998f2e4561f27f7f429fe6103406ecf16e33837470
# V2 hash = 2f42dcf05dd87e6352491ff9d4ea3dc3f854df53d548a8da0c323be42df797b6 (32-bit payload)
# V2 hash = 8301936f439f43579cffe98e11e3224051e2fb890ffe9df680bbbd8db0729387 (64-bit payload)

RULE_SOURCE = """
rule StealC
{
    meta:
        author = "Yung Binary"
    strings:
        $decode_1 = {6A ?? 68 [4] 68 [4] E8}
        $decode_2 = {6A ?? 68 [4] 68 [4] [0-5] E8}
    condition:
        any of them
}
rule StealcV2
{
    meta:
        author = "kevoreilly"
    strings:
        $botnet32 = {AB AB AB AB 89 4B ?? C7 43 ?? 0F 00 00 00 88 0B A0 [4] EB 12 3C 20 74 0B 0F B6 06 8B CB 50 E8}
        $botnet64 = {0F 11 01 48 C7 41 ?? 00 00 00 00 48 8B D9 48 C7 41 ?? 0F 00 00 00 C6 01 00 8A 05 [4] EB ?? 3C 20 74 ?? 48 8B 4B ?? 44 8A 0F}
    condition:
        any of them
}
"""


def yara_scan(raw_data):
    yara_rules = yara.compile(source=RULE_SOURCE)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                yield block.identifier, instance.offset


def _is_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

def xor_data(data, key):
    decoded = bytearray()
    for i in range(len(data)):
        decoded.append(data[i] ^ key[i])
    return decoded


def extract_ascii_string(data: bytes, offset: int, max_length=4096) -> str:
    if offset >= len(data):
        raise ValueError("Offset beyond data bounds")
    end = data.find(b'\x00', offset, offset + max_length)
    if end == -1:
        end = offset + max_length
    return data[offset:end].decode('ascii', errors='replace')


def parse_text(data):
    global domain, uri
    with suppress(Exception):
        lines = data.decode().split("\n")
        if not lines:
            return
        for line in lines:
            if line.startswith("http") and "://" in line:
                domain = line
            elif _is_ip(line):
                domain = line
            if line.startswith("/") and len(line) >= 4 and line[-4] == ".":
                uri = line


def parse_pe(data):
    global domain, uri, botnet_id
    pe = None
    image_base = 0
    last_str = ""
    with suppress(Exception):
        pe = pefile.PE(data=data, fast_load=True)
        if not pe:
            return
        image_base = pe.OPTIONAL_HEADER.ImageBase
        if not image_base:
            return
    for match in yara_scan(data):
        try:
            rule_str_name, str_decode_offset = match
            if rule_str_name.startswith("$botnet"):
                botnet_var = struct.unpack("I", data[str_decode_offset - 4 : str_decode_offset])[0]
                if hasattr(pe, 'OPTIONAL_HEADER'):
                    magic = pe.OPTIONAL_HEADER.Magic
                    if magic == 0x10b: # 32-bit
                        botnet_offset = pe.get_offset_from_rva(botnet_var - image_base)
                    elif magic == 0x20b: # 64-bit
                        botnet_offset = pe.get_offset_from_rva(pe.get_rva_from_offset(str_decode_offset) + botnet_var)
                    if botnet_offset:
                        botnet_id = extract_ascii_string(data, botnet_offset)
            str_size = int(data[str_decode_offset + 1])
            # Ignore size 0 strings
            if not str_size:
                continue
            if rule_str_name.startswith("$decode"):
                key_rva = data[str_decode_offset + 3 : str_decode_offset + 7]
                encoded_str_rva = data[str_decode_offset + 8 : str_decode_offset + 12]
                key_offset = pe.get_offset_from_rva(struct.unpack("i", key_rva)[0] - image_base)
                encoded_str_offset = pe.get_offset_from_rva(struct.unpack("i", encoded_str_rva)[0] - image_base)
                key = data[key_offset : key_offset + str_size]
                encoded_str = data[encoded_str_offset : encoded_str_offset + str_size]
                decoded_str = xor_data(encoded_str, key).decode()
                if last_str in ("http://", "https://"):
                    domain += decoded_str
                elif decoded_str in ("http://", "https://"):
                    domain = decoded_str
                elif "http" in decoded_str and "://" in decoded_str:
                    domain = decoded_str
                elif uri is None and decoded_str.startswith("/") and decoded_str[-4] == ".":
                    uri = decoded_str
                elif last_str[0] == "/" and last_str[-1] == "/":
                    botnet_id = decoded_str
                last_str = decoded_str
        except Exception:
            continue
    return


def extract_config(data):
    global domain, uri, botnet_id
    domain = uri = botnet_id = None
    config_dict = {}

    if data[:2] == b'MZ':
        parse_pe(data)
    else:
        parse_text(data)

    if domain and uri:
        config_dict.setdefault("CNCs", []).append(f"{domain}{uri}")

    if botnet_id:
        config_dict.setdefault("botnet", botnet_id)

    if "CNCs" not in config_dict:
        return {}
    
    return config_dict


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
