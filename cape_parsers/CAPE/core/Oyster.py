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

import ipaddress
import logging
import re
import struct
from contextlib import suppress
from typing import List

import pefile
import yara

log = logging.getLogger(__name__)

DESCRIPTION = "Oyster configuration parser."
AUTHOR = "enzok"
yara_rules = yara.compile(source="""rule Oyster
{
    meta:
        author = "enzok"
        description = "Oyster Payload"
        cape_type = "Oyster Payload"
        hash = "8bae0fa9f589cd434a689eebd7a1fde949cc09e6a65e1b56bb620998246a1650"
    strings:
		$start_exit = {(05 | 00) 00 00 00 2E 96 1E A6}
		$content_type = {F6 CE 56 F4 76 F6 96 2E 86 C6 96 36 0E 0E 86 04 5C A6 0E 9E 2A B4 2E 76 A6 2E 76 F6 C2}
        $domain = {44 5C 44 76 96 86 B6 F6 26 44 34 44}
        $id = {44 5C 44 64 96 44 DE}
        $ip_local = {44 5C 44 36 86 C6 F6 36 FA 0E 96 44 34 44}
        $table_part_1 = {00 80 40 C0 20 A0 60 E0 10 90 50 D0 30 B0 70 F0 08 88 48 C8 28 A8 68}
        $table_part_2 = {97 57 D7 37 B7 77 F7 0F 8F 4F CF 2F AF 6F EF 1F 9F 5F DF 3F BF 7F FF}
		$decode = {0F B6 0? 8D ?? FF 8A [2] 0F B6 80 [4] 88 04 ?? 46 0F B6 C? 0F B6 80 [4] 88 4? 01 3B F7}
    condition:
        4 of them
}
""")

MIN_CHARS = 6


def transform(src, lookup_table):
    length = len(src)
    i = 0
    num = length // 2
    if num > 0:
        pVal = length - 1
        while i < num:
            k = src[pVal]
            n = src[i]
            src[i] = lookup_table[k]
            i += 1
            result = lookup_table[n]
            src[pVal] = result
            pVal -= 1

    return src


def yara_scan(raw_data):
    try:
        return yara_rules.match(data=raw_data)
    except yara.Error as e:
        log.error("Yara scan failed: %s", e)
        return []


def extract_utf16le(data, min_chars=MIN_CHARS):
    results = []
    n = len(data)
    i = 0
    while i < n - 1:
        if 32 <= data[i] <= 126 and data[i + 1] == 0x00:
            start = i
            chars = []
            while i < n - 1 and 32 <= data[i] <= 126 and data[i + 1] == 0x00:
                chars.append(chr(data[i]))
                i += 2

            if len(chars) >= min_chars:
                results.append((start, ''.join(chars)))
        else:
            i += 1

    return results


def is_uri(s: str) -> bool:
    return s.lower().lstrip().startswith(("api/", "/api"))


def is_c2(s: str) -> bool:
    DOMAIN_RE = re.compile(r'^[a-zA-Z0-9.-]+\.(?:com|net)$', re.IGNORECASE)
    IP_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')

    s = s.strip()
    if DOMAIN_RE.match(s):
        return True

    if IP_RE.match(s):
        try:
            ip = ipaddress.IPv4Address(s)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                return False

            return True
        except ipaddress.AddressValueError:
            return False

    return False


def is_useragent(s: str) -> bool:
    return "mozilla" in s.lower()


def is_mutex(s: str) -> bool:
    if s.count('-') < 2:
        return False

    parts = [p.strip() for p in s.split('-') if p.strip()]
    if len(parts) < 3:
        return False

    has_digit = any(any(ch.isdigit() for ch in part) for part in parts)
    long_enough = all(len(part) > 1 for part in parts)
    return has_digit and long_enough


def extract_types(data: bytes):
    uris = []
    c2s = []
    user_agent = None
    mutexes = []

    for off, s in extract_utf16le(data):
        s_str = s.strip()
        if is_uri(s_str) and s_str not in uris:
            uris.append(s_str)

        if is_c2(s_str) and s_str not in c2s:
            c2s.append(s_str)

        if user_agent is None and is_useragent(s_str):
            user_agent = s_str

        if is_mutex(s_str) and s_str not in mutexes:
            mutexes.append(s_str)

    return uris, c2s, user_agent, mutexes


def make_endpoints(c2s: List[str], uris: List[str]) -> List[str]:
    endpoints = []
    for c2 in c2s:
        for uri in uris:
            endpoints.append(f"https://{c2}/{uri.lstrip('/')}")

    return endpoints


def extract_config(filebuf):
    yara_hits = yara_scan(filebuf)
    config = {}

    for hit in yara_hits:
        if hit.rule == "Oyster":
            start_offset = ""
            lookup_va = ""

            for item in hit.strings:
                if "$start_exit" == item.identifier:
                    start_offset = item.instances[0].offset

                if "$decode" == item.identifier:
                    decode_offset = item.instances[0].offset
                    lookup_va = filebuf[decode_offset + 12: decode_offset + 16]

            if not (start_offset and lookup_va):
                continue

            try:
                pe = pefile.PE(data=filebuf, fast_load=True)
                lookup_offset = pe.get_offset_from_rva(struct.unpack("I", lookup_va)[0] - pe.OPTIONAL_HEADER.ImageBase)
                lookup_table = filebuf[lookup_offset: lookup_offset + 256]
                data = filebuf[start_offset + 4: start_offset + 8092]
                hex_strings = re.split(rb"\x00+", data)
                hex_strings = [s for s in hex_strings if s]
                str_vals = []
                c2 = []
                dll_version = ""

                c2_pattern = r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?!txt\b|dll\b|exe\b)[a-zA-Z]{2,}"

                for item in hex_strings:
                    with suppress(Exception):
                        decoded = transform(bytearray(item), bytearray(lookup_table)).decode("utf-8")

                    if not decoded:
                        continue

                    if "http" in decoded:
                        if "\r\n" in decoded:
                            c2.extend(list(filter(None, decoded.split("\r\n"))))
                        else:
                            c2.append(decoded)
                    elif "dll_version" in decoded:
                        dll_version = decoded.split('":"')[-1]
                    elif "api" in decoded or "Content-Type" in decoded:
                        str_vals.append(decoded)
                    else:
                        c2_matches = re.findall(c2_pattern, decoded)
                        if c2_matches:
                            c2.extend(c2_matches)

                config = {"CNCs": c2, 'version': dll_version, "raw": {"Strings": str_vals, }, }
                return config
            except pefile.PEFormatError as e:
                log.debug("PEFormatError: %s", e)
            except Exception as e:
                log.error("Error: %s", e)

    if not config:
        urls = []
        uris, c2s, useragent, mutexes = extract_types(filebuf)
        if uris and c2s:
            urls = make_endpoints(c2s, uris)

        config = {"CNCs": urls, "user_agent": useragent, "mutex": mutexes, }

    return config


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
