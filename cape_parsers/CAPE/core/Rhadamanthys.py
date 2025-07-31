import struct
import base64
import re
import json


DESCRIPTION = "Rhadamanthys parser"
AUTHOR = "kevoreilly, YungBinary"


def mask32(x):
    return x & 0xFFFFFFFF


def add32(x, y):
    return mask32(x + y)


def left_rotate(x, n):
    return mask32(x << n) | (x >> (32 - n))


def quarter_round(block, a, b, c, d):
    block[a] = add32(block[a], block[b])
    block[d] ^= block[a]
    block[d] = left_rotate(block[d], 16)
    block[c] = add32(block[c], block[d])
    block[b] ^= block[c]
    block[b] = left_rotate(block[b], 12)
    block[a] = add32(block[a], block[b])
    block[d] ^= block[a]
    block[d] = left_rotate(block[d], 8)
    block[c] = add32(block[c], block[d])
    block[b] ^= block[c]
    block[b] = left_rotate(block[b], 7)


def chacha20_permute(block):
    for doubleround in range(10):
        quarter_round(block, 0, 4, 8, 12)
        quarter_round(block, 1, 5, 9, 13)
        quarter_round(block, 2, 6, 10, 14)
        quarter_round(block, 3, 7, 11, 15)
        quarter_round(block, 0, 5, 10, 15)
        quarter_round(block, 1, 6, 11, 12)
        quarter_round(block, 2, 7, 8, 13)
        quarter_round(block, 3, 4, 9, 14)


def words_from_bytes(b):
    assert len(b) % 4 == 0
    return [int.from_bytes(b[4 * i : 4 * i + 4], "little") for i in range(len(b) // 4)]


def bytes_from_words(w):
    return b"".join(word.to_bytes(4, "little") for word in w)


def chacha20_block(key, nonce, blocknum):
    # This implementation doesn't support 16-byte keys.
    assert len(key) == 32
    assert len(nonce) == 12
    assert blocknum < 2**32
    constant_words = words_from_bytes(b"expand 32-byte k")
    key_words = words_from_bytes(key)
    nonce_words = words_from_bytes(nonce)
    # fmt: off
    original_block = [
        constant_words[0],  constant_words[1],  constant_words[2],  constant_words[3],
        key_words[0],       key_words[1],       key_words[2],       key_words[3],
        key_words[4],       key_words[5],       key_words[6],       key_words[7],
        mask32(blocknum),   nonce_words[0],     nonce_words[1],     nonce_words[2],
    ]
    # fmt: on
    permuted_block = list(original_block)
    chacha20_permute(permuted_block)
    for i in range(len(permuted_block)):
        permuted_block[i] = add32(permuted_block[i], original_block[i])
    return bytes_from_words(permuted_block)


def chacha20_stream(key, nonce, length, blocknum):
    output = bytearray()
    while length > 0:
        block = chacha20_block(key, nonce, blocknum)
        take = min(length, len(block))
        output.extend(block[:take])
        length -= take
        blocknum += 1
    return output


def decrypt_config(data):
    decrypted_config = b"\x21\x52\x48\x59"
    data_len = len(data)
    v3 = 0
    while True:
        v8 = 4
        while v8:
            if data_len <= (v3 + 4):
                return decrypted_config
            a = data[v3]
            b = data[v3 + 4]
            c = a ^ b
            decrypted_config += bytes([c])
            v8 -= 1
            v3 += 1


def chacha20_xor(custom_b64_decoded, key, nonce):
    message_len = len(custom_b64_decoded)
    key_stream = chacha20_stream(key, nonce, message_len, 0x80)

    xor_key = bytearray()
    for i in range(message_len):
        xor_key.append(custom_b64_decoded[i] ^ key_stream[i])

    return xor_key


def extract_strings(data, minchars, maxchars):
    apat = b"([\x20-\x7e]{" + str(minchars).encode() + b"," + str(maxchars).encode() + b"})\x00"
    strings = [string.decode() for string in re.findall(apat, data)]
    match = re.search(apat, data)
    if not match:
        return None
    upat = b"((?:[\x20-\x7e][\x00]){" + str(minchars).encode() + b"," + str(maxchars).encode() + b"})\x00\x00"
    strings.extend(str(ws.decode("utf-16le")) for ws in re.findall(upat, data))
    return strings


def extract_c2_url(data):
    pattern = b"(http[\x20-\x7e]+)\x00"
    match = re.search(pattern, data)
    return match.group(1).decode()


def is_potential_custom_base64(string):
    custom_alphabet = "ABC1fghijklmnop234NOPQRSTUVWXY567DEFGHIJKLMZ089abcdeqrstuvwxyz-|"
    for c in string:
        if c not in custom_alphabet:
            return False
    return True


def custom_b64decode(data):
    """Decodes base64 data using a custom alphabet."""
    standard_alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    custom_alphabet = b"ABC1fghijklmnop234NOPQRSTUVWXY567DEFGHIJKLMZ089abcdeqrstuvwxyz-|"
    # Translate the data back to the standard alphabet before decoding
    table = bytes.maketrans(custom_alphabet, standard_alphabet)
    return base64.b64decode(data.translate(table), validate=True)


def extract_config(data):
    config_dict = {}
    magic = struct.unpack("I", data[:4])[0]
    if magic == 0x59485221:
        config_dict["CNCs"] = [data[24:].split(b"\0", 1)[0].decode()]
        return config_dict
    else:
        key = b"\x52\xAB\xDF\x06\xB6\xB1\x3A\xC0\xDA\x2D\x22\xDC\x6C\xD2\xBE\x6C\x20\x17\x69\xE0\x12\xB5\xE6\xEC\x0E\xAB\x4C\x14\x73\x4A\xED\x51"
        nonce = b"\x5F\x14\xD7\x9C\xFC\xFC\x43\x9E\xC3\x40\x6B\xBA"

        extracted_strings = extract_strings(data, 0x100, 0x100)
        for string in extracted_strings:
            try:
                if not is_potential_custom_base64(string):
                    continue

                custom_b64_decoded = custom_b64decode(string)
                xor_key = chacha20_xor(custom_b64_decoded, key, nonce)
                decrypted_config = decrypt_config(xor_key)
                reexecution_delay = int.from_bytes(decrypted_config[5:7], byteorder="little")

                c2_url = extract_c2_url(decrypted_config)
                if not c2_url:
                    continue
                config_dict = {"raw": {"Reexecution_delay": reexecution_delay}, "CNCs": [c2_url]}
                return config_dict
            except Exception:
                continue


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        config_json = json.dumps(extract_config(f.read()), indent=4)
        print(config_json)
