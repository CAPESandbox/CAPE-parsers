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

import pefile

DESCRIPTION = "AxolotlLoader payload dumper."
AUTHOR = "enzok"

log = logging.getLogger(__name__)

MIN_WORD_LEN = 3
COVERAGE_THRESHOLD = 0.70
WORD_NUL_RE = re.compile(rb"[A-Za-z0-9]{%d,}\x00" % MIN_WORD_LEN)


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

        yield data[offset : offset + entry.data.struct.Size]


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


def extract_payload(data: bytes):
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    payload = b""

    for raw in iter_resources(pe, data):
        if not looks_like_wordlist(raw):
            continue

        words = [word for word in raw.split(b"\x00") if word]
        decoded = decode_payload(words)
        if len(decoded) > len(payload):
            payload = decoded

    return payload


def extract_config(data: bytes):
    config = {}

    try:
        payload = extract_payload(data)
    except Exception as e:
        log.error("Failed to extract payload: %s", e)
        return config

    if payload:
        config["dump_files"] = {"payload": payload}

    return config


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        conf = extract_config(f.read())

    for name, payload in conf.get("dump_files", {}).items():
        print(f"{name}: {len(payload)} bytes")
