# Copyright (C) 2026
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
import struct

import pefile

DESCRIPTION = "AxolotlLoader payload dumper."
AUTHOR = "enzok"

log = logging.getLogger(__name__)

MIN_WORD_LEN = 3
COVERAGE_THRESHOLD = 0.70
STREAM_SEP = b"\x00\x00"
STREAM_PROBE_LEN = 256
WORD_NUL_RE = re.compile(rb"[A-Za-z0-9]{%d,}\x00" % MIN_WORD_LEN)

# lea r8, [rip+start] / lea r9, [rip+end] / mov rsi, key
# xor [r8], rsi / add r8, 8 / cmp r8, r9 / jb
XOR_STUB_RE = re.compile(
    rb"\x4c\x8d\x05(....)\x4c\x8d\x0d(....)\x48\xbe(.{8})"
    rb"\x49\x31\x30\x49\x83\xc0\x08\x4d\x39\xc8\x72",
    re.DOTALL,
)

HTTPS_PORT = 443
MIN_PORT = 80

# call over the string, so the return address is a pointer to it
HOST_RE = re.compile(rb"\xe8(.)\x00\x00\x00([a-z0-9][a-z0-9.\-]{3,62}\.[a-z]{2,12})\x00", re.DOTALL)
URI_RE = re.compile(rb"(/[A-Za-z0-9._~/\-]{3,120})\x00")
INIT_URI_RE = re.compile(rb"/api/init/([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})")
# mov r8, port / xor r9, r9 -- WinHttpConnect's nServerPort and its reserved argument
PORT_RE = re.compile(rb"\x49\xc7\xc0(....)\x4d\x31\xc9", re.DOTALL)
# cmp word [rax], ".." / cmp byte [rax+2], "." -- the scan for the dead drop's marker
MARKER_RE = re.compile(rb"\x66\x81\x38(..).{0,8}?\x80\x78\x02(.)", re.DOTALL)


def iter_resources(pe, data: bytes):
    """Yield the raw bytes of every resource leaf, at any tree depth.

    Reads through get_offset_from_rva into the original buffer rather than
    get_memory_mapped_image, which zero-fills any section it considers bogus
    (e.g. one whose raw data runs past EOF) and would hide the payload.
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return

    stack = list(pe.DIRECTORY_ENTRY_RESOURCE.entries)

    while stack:
        entry = stack.pop()

        if hasattr(entry, "directory"):
            stack.extend(entry.directory.entries)
            continue

        if not hasattr(entry, "data"):
            continue

        try:
            offset = pe.get_offset_from_rva(entry.data.struct.OffsetToData)
        except Exception:
            continue

        yield data[offset: offset + entry.data.struct.Size]


def looks_like_wordlist(raw: bytes):
    if not raw:
        return False

    covered = sum(len(match) for match in WORD_NUL_RE.findall(raw))

    return covered / len(raw) >= COVERAGE_THRESHOLD


def decode_payload(words):
    """
    Turns the wordlist back into the hidden binary data.

    The first 256 different words are just a decoder ring: the 1st new word
    means byte 0, the 2nd new word means byte 1, and so on up to byte 255.

    After that, every word is looked up in that ring: if it matches one of
    those 256 words exactly, its byte value gets written out. If it doesn't
    match (it's a decoy word with extra letters/numbers tacked on), it's
    skipped -- it was only there as padding.
    """
    alphabet = {}
    i = 0
    n = len(words)

    while i < n and len(alphabet) < 256:
        alphabet.setdefault(words[i], len(alphabet))
        i += 1

    return bytes(alphabet[word] for word in words[i:] if word in alphabet)


def carve_decoded_stream(raw: bytes, stream: bytes):
    """Return the payload the loader already decoded over the front of the stream.

    Decoding happens in place: one output byte lands at the head of the encoded
    stream for every fixed-width word consumed from further along it. In a memory
    dump taken afterwards that output is sitting at the stream start and the words
    encoding the leading payload bytes are gone, so the length can no longer come
    from the decode and is taken from the stream geometry instead.
    """
    stride = len(raw.split(b"\x00", 1)[0]) + 1

    return stream[: (len(stream) + 1) // stride]


def parse_xor_stub(payload: bytes):
    """Return (key, start, end) for the payload's self-decrypting XOR stub.

    The stub carries everything needed to undo the pass: the key as a mov
    immediate, the bounds as rip-relative leas. It sits in the payload's plaintext
    head, so it reads the same whether or not the body has been decrypted yet.
    """
    match = XOR_STUB_RE.search(payload)
    if not match:
        return None

    start = match.start(1) + 4 + struct.unpack("<i", match.group(1))[0]
    end = match.start(2) + 4 + struct.unpack("<i", match.group(2))[0]

    if not 0 <= start < end <= len(payload):
        log.error("XOR stub bounds outside payload: %#x-%#x of %#x", start, end, len(payload))
        return None

    return match.group(3), start, end


def decrypt_body(payload: bytes):
    """Undo the payload's own 8-byte XOR pass over its body.

    A payload carved out of a memory dump has already run this itself, which the
    key left standing where the body's zero fill was gives away.
    """
    stub = parse_xor_stub(payload)
    if not stub:
        return payload

    key, start, end = stub

    if key * 2 not in payload[start:end]:
        return payload

    body = bytes(byte ^ key[i % len(key)] for i, byte in enumerate(payload[start:end]))

    return payload[:start] + body + payload[end:]


def extract_network(payload: bytes):
    """Config for the dead-drop rendezvous the loader uses to reach its real C2.

    It fetches a page on a legitimate forum, pulls the C2 out of a marker-delimited
    blob on it, then talks to that host under the init URI -- so the drop is the only
    endpoint whose host is known without running the sample, and the init URI is
    reported on its own rather than hung off a host it never belonged to.
    """
    config = {}

    hosts = [
        match.group(2)
        for match in HOST_RE.finditer(payload)
        if match.group(1)[0] == len(match.group(2)) + 1 and not match.group(2).endswith(b".dll")
    ]
    ports = [
        port
        for (port,) in (struct.unpack("<I", match.group(1)) for match in PORT_RE.finditer(payload))
        if MIN_PORT <= port <= 0xFFFF
    ]
    init = INIT_URI_RE.search(payload)
    drops = [match.group(1) for match in URI_RE.finditer(payload) if not init or match.group(1) != init.group(0)]

    if hosts and ports and drops:
        scheme = "https" if ports[0] == HTTPS_PORT else "http"
        config["CNCs"] = ["%s://%s:%d%s" % (scheme, hosts[0].decode(), ports[0], drops[0].decode())]

    raw = {}

    if init:
        config["campaign"] = init.group(1).decode()
        raw["init_uri"] = init.group(0).decode()

    marker = MARKER_RE.search(payload)
    if marker:
        raw["deaddrop_marker"] = (marker.group(1) + marker.group(2)).decode(errors="replace")

    if raw:
        config["raw"] = raw

    return config


def extract_payload(data: bytes):
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    payload = b""

    for raw in iter_resources(pe, data):
        if not looks_like_wordlist(raw):
            continue

        # An empty word separates the alphabet and its padding from the encoded stream.
        stream = raw.partition(STREAM_SEP)[2]

        if stream and not looks_like_wordlist(stream[:STREAM_PROBE_LEN]):
            decoded = carve_decoded_stream(raw, stream)
        else:
            words = [word for word in raw.split(b"\x00") if word]
            decoded = decode_payload(words)

        if len(decoded) > len(payload):
            payload = decoded

    return decrypt_body(payload)


def extract_config(data: bytes):
    config = {}

    try:
        payload = extract_payload(data)
    except Exception as e:
        log.error("Failed to extract payload: %s", e)
        return config

    if payload:
        config.update(extract_network(payload))
        stub = parse_xor_stub(payload)
        if stub:
            config["cryptokey"] = stub[0].hex()
            config["cryptokey_type"] = "XOR"

        config["dump_files"] = {"payload": payload}
    return config


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        conf = extract_config(f.read())

    for name, payload in conf.pop("dump_files", {}).items():
        print(f"{name}: {len(payload)} bytes")

    for key, value in conf.items():
        print(f"{key}: {value}")
