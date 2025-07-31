import struct
import pefile
import yara
from contextlib import suppress

# Hash = 69ba4e2995d6b11bb319d7373d150560ea295c02773fe5aa9c729bfd2c334e1e

RULE_SOURCE = """rule Arkei
{
    meta:
        author = "Yung Binary"
    strings:
        $decode_1 = {
            6A ??
            68 ?? ?? ?? ??
            68 ?? ?? ?? ??
            E8 ?? ?? ?? ??
        }
        $decode_2 = {
            6A ??
            68 ?? ?? ?? ??
            68 ?? ?? ?? ??
            [0-5]
            E8 ?? ?? ?? ??
        }
    condition:
        any of them
}"""


def yara_scan(raw_data):
    yara_rules = yara.compile(source=RULE_SOURCE)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                yield block.identifier, instance.offset


def xor_data(data, key):
    decoded = bytearray()
    for i in range(len(data)):
        decoded.append(data[i] ^ key[i])
    return decoded


def extract_config(data):
    config = {}

    # Attempt to extract via old method
    with suppress(Exception):
        domain = ""
        uri = ""
        lines = data.decode().split("\n")
        for line in lines:
            if line.startswith("http") and "://" in line:
                domain = line
            if line.startswith("/") and line[-4] == ".":
                uri = line
        if domain and uri:
            config.setdefault("CNCs", []).append(f"{domain}{uri}")
            return config

    # Try with new method

    # config_dict["Strings"] = []
    pe = pefile.PE(data=data, fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    domain = ""
    uri = ""
    botnet_id = ""
    last_str = ""
    for match in yara_scan(data):
        try:
            rule_str_name, str_decode_offset = match
            str_size = int(data[str_decode_offset + 1])
            # Ignore size 0 strings
            if not str_size:
                continue

            if rule_str_name.startswith("$decode"):
                key_rva = data[str_decode_offset + 3 : str_decode_offset + 7]
                encoded_str_rva = data[str_decode_offset + 8 : str_decode_offset + 12]
                # dword_rva = data[str_decode_offset + 21 : str_decode_offset + 25]

            key_offset = pe.get_offset_from_rva(struct.unpack("i", key_rva)[0] - image_base)
            encoded_str_offset = pe.get_offset_from_rva(struct.unpack("i", encoded_str_rva)[0] - image_base)
            # dword_offset = struct.unpack("i", dword_rva)[0]
            # dword_name = f"dword_{hex(dword_offset)[2:]}"

            key = data[key_offset : key_offset + str_size]
            encoded_str = data[encoded_str_offset : encoded_str_offset + str_size]
            decoded_str = xor_data(encoded_str, key).decode()
            # config_dict["Strings"].append({dword_name : decoded_str})

            if last_str in ("http://", "https://"):
                domain += decoded_str
            elif decoded_str in ("http://", "https://"):
                domain = decoded_str
            elif "http" in decoded_str and "://" in decoded_str:
                domain = decoded_str
            elif uri == "" and decoded_str.startswith("/") and decoded_str[-4] == ".":
                uri = decoded_str
            elif last_str.startswith("/") and last_str[-4] == ".":
                botnet_id = decoded_str
                break

            last_str = decoded_str

        except Exception:
            continue

    if domain and uri:
        config.setdefault("CNCs", []).append(f"{domain}{uri}")

    if botnet_id:
        config.setdefault("botnet", botnet_id)

    return config


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
