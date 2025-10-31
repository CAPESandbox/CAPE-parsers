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
    decrypted_config = b""
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


def extract_base64_strings(data, minchars, maxchars):
    apat = b"([A-Za-z0-9-|]{" + str(minchars).encode() + b"," + str(maxchars).encode() + b"})\x00"
    strings = [s.decode() for s in re.findall(apat, data)]
    upat = b"((?:[A-Za-z0-9-|]\x00){" + str(minchars).encode() + b"," + str(maxchars).encode() + b"})\x00\x00"
    strings.extend(ws.decode("utf-16le") for ws in re.findall(upat, data))
    return strings


def extract_c2_url(data):
    pattern = b"(http[\x20-\x7e]+)\x00"
    match = re.search(pattern, data)
    if match:
        return match.group(1).decode()


def custom_b64decode(data: bytes, custom_alphabet: bytes):
    """Decodes base64 data using a custom alphabet."""
    standard_alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    # Translate the data back to the standard alphabet before decoding
    table = bytes.maketrans(custom_alphabet, standard_alphabet)
    return base64.b64decode(data.translate(table), validate=True)


def lzo_noheader_decompress(data: bytes, decompressed_size: int):
    src = 0
    dst = bytearray()
    length = len(data)

    while src < length:
        ctrl = data[src]
        src += 1

        if ctrl == 0x20:
            match_len = data[src]
            src += 1
            start = len(dst) - match_len - 1
            end = start + 3
            #print(f"Control code: {hex(ctrl)}, Offset backtrack length: {hex(match_len)}, Current offset: {hex(len(dst))}, New offset: {hex(start)}")
            dst.extend(dst[start:end])

        elif ctrl >= 0xE0 or ctrl == 0x40:
            x = ((ctrl >> 5) - 1) + 3
            if ctrl >= 0xE0:
                copy_len = data[src] + x
            elif ctrl == 0x40:
                copy_len = x
            start = data[src + 1]
            if ctrl == 0x40:
                start = data[src]
            if ctrl >= 0xE0:
                src += 2
            elif ctrl == 0x40:
                src += 1
            offset = len(dst) - start - 1
            #print(f"Control code: {hex(ctrl)}, Offset backtrack length: {hex(start)}, Current offset: {hex(len(dst))}, New offset: {hex(len(dst) - start)}, Length to copy: {hex(copy_len)}")
            dst.extend(dst[offset:offset+copy_len])

        else:
            # Literal run
            literal_len = (ctrl & 0x1F) + 1
            #print(f"Control code: {hex(ctrl)}, Literal length: {hex(literal_len)}")
            dst.extend(data[src:src+literal_len])
            src += literal_len

        if len(dst) == decompressed_size:
            return bytes(dst)


def parse_compression_header(config: bytes):
    """Parse compressed size, decompressed size, and data offset from config"""

    # 0x2A when looking at the config in memory
    base_offset = 0x26

    # Compressed data offset field, for calculating the offset to the compressed buffer
    comp_offset_field = config[base_offset]
    # Number of bytes the field spans
    comp_offset_size_len = (comp_offset_field & 3) + 1
    for i in range(1, comp_offset_size_len):
        comp_offset_field |= config[base_offset + i] << (8 * i)
    
    comp_size_offset = comp_offset_field >> 2

    # Compressed size field, for finding the size of the compressed buffer
    comp_offset = base_offset + comp_offset_size_len
    comp_size_field = config[comp_offset]
    # Number of bytes the field spans
    comp_size_len = (comp_size_field & 3) + 1
    for i in range(1, comp_size_len):
        comp_size_field |= config[comp_offset + i] << (8 * i)

    # Decompressed size field
    decomp_field_offset = base_offset + comp_offset_size_len + comp_size_len
    decomp_size_field = config[decomp_field_offset]
    # Number of bytes the field spans
    decomp_field_len = (decomp_size_field & 3) + 1
    for i in range(1, decomp_field_len):
        decomp_size_field |= config[decomp_field_offset + i] << (8 * i)

    # Calculate return values
    decompressed_size = decomp_size_field >> 2
    compressed_data_offset = decomp_field_offset + decomp_field_len + comp_size_offset
    compressed_size_key = config[0x28] << 8
    compressed_size = (compressed_size_key | comp_size_field) >> 2
    compressed_data = config[compressed_data_offset : compressed_data_offset + compressed_size]

    return {
        "compressed_size": compressed_size,
        "decompressed_size": decompressed_size,
        "compressed_data": compressed_data
    }


def extract_config(data):
    config_dict = {}
    magic = struct.unpack("I", data[:4])[0]
    if magic == 0x59485221:
        config_dict["CNCs"] = [data[24:].split(b"\0", 1)[0].decode()]
        return config_dict
    else:
        key = b"\x52\xAB\xDF\x06\xB6\xB1\x3A\xC0\xDA\x2D\x22\xDC\x6C\xD2\xBE\x6C\x20\x17\x69\xE0\x12\xB5\xE6\xEC\x0E\xAB\x4C\x14\x73\x4A\xED\x51"
        nonce = b"\x5F\x14\xD7\x9C\xFC\xFC\x43\x9E\xC3\x40\x6B\xBA"

        custom_alphabets = [
            b"ABC1fghijklmnop234NOPQRSTUVWXY567DEFGHIJKLMZ089abcdeqrstuvwxyz-|",
            b"4NOPQRSTUVWXY567DdeEqrstuvwxyz-ABC1fghop23Fijkbc|lmnGHIJKLMZ089a"
        ]

        # Extract base64 strings
        extracted_strings = extract_base64_strings(data, 140, 256)
        if not extracted_strings:
            return config_dict

        
        pattern = re.compile(b'.\x80')
        for string in extracted_strings:
            try:
                custom_b64_decoded = custom_b64decode(string, custom_alphabets[0])

                xor_key = chacha20_xor(custom_b64_decoded, key, nonce)

                # Decrypted, but may still be the compressed malware configuration
                config = decrypt_config(xor_key)
                # Attempt to extract C2 url, only works in version prior to 0.9.2
                c2_url = extract_c2_url(config)
                if c2_url:
                    config_dict = {"CNCs": [c2_url]}
                    return config_dict
                else:
                    # Handle new variants that compress the Command and Control server(s)
                    custom_b64_decoded = custom_b64decode(string, custom_alphabets[1])
                    xor_key = chacha20_xor(custom_b64_decoded, key, nonce)
                    config = decrypt_config(xor_key)

                    parsed = parse_compression_header(config)
                    if not parsed:
                        return config_dict

                    decompressed = lzo_noheader_decompress(parsed['compressed_data'], parsed['decompressed_size'])

                    cncs = [f"https://{chunk.decode()}" for chunk in pattern.split(decompressed) if chunk]
                    if cncs:
                        config_dict = {"CNCs": cncs}
                        return config_dict

            except Exception:
                continue
        
        return config_dict


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        config_json = json.dumps(extract_config(f.read()), indent=4)
        print(config_json)
