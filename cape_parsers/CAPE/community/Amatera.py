import base64
import json
import pefile
from cape_parsers.utils import yara_wrapper as yara
import struct
from contextlib import suppress

DESCRIPTION = "Amatera Stealer parser"
AUTHOR = "YungBinary"

RULE_SOURCE = """
rule AmateraDecrypt
{
    meta:
        author = "YungBinary"
        description = "Find Amatera XOR key"
    strings:
        $decrypt_global = {
            A1 ?? ?? ?? ??                  // mov     eax, dword ptr ds:szXorKey ; "852149723"
            89 45 ??                        // mov     dword ptr [ebp+xor_key], eax
            8B 0D ?? ?? ?? ??               // mov     ecx, dword ptr ds:szXorKey+4 ; "49723"
            89 4D ??                        // mov     dword ptr [ebp+xor_key+4], ecx
            66 8B 15 ?? ?? ?? ??            // mov     dx, word ptr ds:szXorKey+8 ; "3"
            66 89 55 ??                     // mov     word ptr [ebp+xor_key+8], dx
            8D 45 ??                        // lea     eax, [ebp+xor_key]
            50                              // push    eax
            E8                              // call
        }
        $decrypt_stack = {
            83 EC 1C                        // sub     esp, 1Ch
            56                              // push    esi
            89 ?? ??                        // mov     [ebp+var], reg
            C6 45 ?? ??                     // mov     [ebp+char_1], imm
            C6 45 ?? ??                     // mov     [ebp+char_2], imm
        }
    condition:
        uint16(0) == 0x5A4D and ($decrypt_global or $decrypt_stack)
}
"""

RULE_SOURCE_AES_KEY = """
rule AmateraAESKey
{
    meta:
        author = "YungBinary"
        description = "Find Amatera AES key"
    strings:
        $aes_key_on_stack = {
            83 EC 2C                        // sub     esp, 2Ch
            C6 45 D4 ??                     // mov     byte ptr [ebp-2Ch], ??
            C6 45 D5 ??                     // mov     byte ptr [ebp-2Bh], ??
            C6 45 D6 ??                     // mov     byte ptr [ebp-2Ah], ??
            C6 45 D7 ??                     // mov     byte ptr [ebp-29h], ??
            C6 45 D8 ??                     // mov     byte ptr [ebp-28h], ??
            C6 45 D9 ??                     // mov     byte ptr [ebp-27h], ??
            C6 45 DA ??                     // mov     byte ptr [ebp-26h], ??
            C6 45 DB ??                     // mov     byte ptr [ebp-25h], ??
            C6 45 DC ??                     // mov     byte ptr [ebp-24h], ??
            C6 45 DD ??                     // mov     byte ptr [ebp-23h], ??
            C6 45 DE ??                     // mov     byte ptr [ebp-22h], ??
            C6 45 DF ??                     // mov     byte ptr [ebp-21h], ??
            C6 45 E0 ??                     // mov     byte ptr [ebp-20h], ??
            C6 45 E1 ??                     // mov     byte ptr [ebp-1Fh], ??
            C6 45 E2 ??                     // mov     byte ptr [ebp-1Eh], ??
            C6 45 E3 ??                     // mov     byte ptr [ebp-1Dh], ??
            C6 45 E4 ??                     // mov     byte ptr [ebp-1Ch], ??
            C6 45 E5 ??                     // mov     byte ptr [ebp-1Bh], ??
            C6 45 E6 ??                     // mov     byte ptr [ebp-1Ah], ??
            C6 45 E7 ??                     // mov     byte ptr [ebp-19h], ??
            C6 45 E8 ??                     // mov     byte ptr [ebp-18h], ??
            C6 45 E9 ??                     // mov     byte ptr [ebp-17h], ??
            C6 45 EA ??                     // mov     byte ptr [ebp-16h], ??
            C6 45 EB ??                     // mov     byte ptr [ebp-15h], ??
            C6 45 EC ??                     // mov     byte ptr [ebp-14h], ??
            C6 45 ED ??                     // mov     byte ptr [ebp-13h], ??
            C6 45 EE ??                     // mov     byte ptr [ebp-12h], ??
            C6 45 EF ??                     // mov     byte ptr [ebp-11h], ??
            C6 45 F0 ??                     // mov     byte ptr [ebp-10h], ??
            C6 45 F1 ??                     // mov     byte ptr [ebp-0Fh], ??
            C6 45 F2 ??                     // mov     byte ptr [ebp-0Eh], ??
            C6 45 F3 ??                     // mov     byte ptr [ebp-0Dh], ??
            C7 45 F4 10 00 00 00            // mov     dword ptr [ebp-0Ch], 10h
        }
    condition:
        uint16(0) == 0x5A4D and $aes_key_on_stack
}
"""

B64_CHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def yara_scan(raw_data: bytes, rule_source: str):
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                return instance.offset


def xor_data(data, key):
    decoded = bytearray()
    for i in range(len(data)):
        decoded.append(key[i % len(key)] ^ data[i])
    return decoded


def decode_and_decrypt(data_bytes, xor_key):
    if not data_bytes:
        return ""

    clean_bytes = data_bytes.rstrip(b"\x00")

    # Heuristic: Check if valid Base64
    if any(b not in B64_CHARS for b in clean_bytes):
        return clean_bytes.decode("utf-8", errors="ignore")

    try:
        decoded = base64.b64decode(clean_bytes, validate=True)
        decrypted = xor_data(decoded, xor_key)
        # Heuristic: Check if result is printable ASCII
        if all(0x20 <= b <= 0x7E for b in decrypted if b != 0):
            return decrypted.decode("utf-8", errors="ignore").rstrip("\x00")
    except Exception:
        pass

    return clean_bytes.decode("utf-8", errors="ignore")


def extract_config(data):
    config_dict = {}

    with suppress(Exception):
        pe = pefile.PE(data=data)
        image_base = pe.OPTIONAL_HEADER.ImageBase

        offset = yara_scan(data, RULE_SOURCE)
        if offset is None:
            return config_dict

        key_str = b""
        if data[offset] == 0xA1:  # $decrypt_global
            key_str_va = struct.unpack("i", data[offset + 1 : offset + 5])[0]
            key_str = (
                pe.get_string_at_rva(key_str_va - image_base, max_length=20) + b"\x00"
            )

        elif data[offset] == 0x83:  # $decrypt_stack
            key_bytes = bytearray()
            # Skip sub/push/mov reg (7 bytes)
            current_idx = offset + 7
            for _ in range(32):
                if data[current_idx] != 0xC6 or data[current_idx + 1] != 0x45:
                    break
                val = data[current_idx + 3]
                if val == 0x00:
                    break
                key_bytes.append(val)
                current_idx += 4
            key_str = key_bytes + b"\x00"

        if key_str:
            config_dict["xor_key"] = key_str.rstrip(b"\x00").decode(
                "utf-8", errors="ignore"
            )

        aes_key_offset = yara_scan(data, RULE_SOURCE_AES_KEY)
        if aes_key_offset:
            aes_key = bytearray()
            aes_block = data[aes_key_offset : aes_key_offset + 131]
            for i in range(0, len(aes_block) - 4, 4):
                aes_key.append(aes_block[i + 6])
            config_dict["cryptokey"] = aes_key.hex()
            config_dict["cryptokey_type"] = "AES"

        data_section = next(
            (
                s
                for s in pe.sections
                if s.Name.decode().strip("\x00").lower() == ".data"
            ),
            None,
        )
        if data_section:
            # First 16 bytes = 4 pointers
            pointers_raw = pe.get_data(data_section.VirtualAddress, 16)
            if len(pointers_raw) == 16:
                ptrs = struct.unpack("4I", pointers_raw)
                extracted = []

                for ptr in ptrs:
                    rva = ptr - image_base
                    if 0 < rva < pe.OPTIONAL_HEADER.SizeOfImage:
                        extracted.append(pe.get_string_at_rva(rva))
                    else:
                        extracted.append(b"")

                if len(extracted) == 4:
                    config_dict["payload_guid_1"] = decode_and_decrypt(
                        extracted[0], key_str
                    )
                    config_dict["payload_guid_2"] = decode_and_decrypt(
                        extracted[1], key_str
                    )
                    config_dict["fake_c2"] = decode_and_decrypt(extracted[2], key_str)

                    real_c2 = decode_and_decrypt(extracted[3], key_str)
                    config_dict["CNCs"] = [f"https://{real_c2}"]

    return config_dict


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(json.dumps(extract_config(f.read()), indent=4))
