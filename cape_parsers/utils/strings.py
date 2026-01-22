# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import re
import yara
import logging
from pathlib import Path

try:
    import re2 as re

    HAVE_RE2 = True
except ImportError:
    import re

    HAVE_RE2 = False


log = logging.getLogger(__name__)


def bytes2str(convert):
    """Converts bytes to string
    @param convert: string as bytes.
    @return: string.
    """
    if isinstance(convert, bytes):
        try:
            convert = convert.decode()
        except UnicodeDecodeError:
            convert = "".join(chr(_) for _ in convert)

        return convert

    if isinstance(convert, bytearray):
        try:
            convert = convert.decode()
        except UnicodeDecodeError:
            convert = "".join(chr(_) for _ in convert)

        return convert

    items = []
    if isinstance(convert, dict):
        tmp_dict = {}
        items = convert.items()
        for k, v in items:
            if isinstance(v, bytes):
                try:
                    tmp_dict[k] = v.decode()
                except UnicodeDecodeError:
                    tmp_dict[k] = "".join(str(ord(_)) for _ in v)
            elif isinstance(v, str):
                tmp_dict[k] = v
        return tmp_dict
    elif isinstance(convert, list):
        converted_list = []
        items = enumerate(convert)
        for k, v in items:
            if isinstance(v, bytes):
                try:
                    converted_list.append(v.decode())
                except UnicodeDecodeError:
                    converted_list.append("".join(str(ord(_)) for _ in v))

        return converted_list

    return convert


def extract_strings(filepath: str = False, data: bytes = False, on_demand: bool = False, dedup: bool = False, minchars: int = 5):
    if minchars == 0:
        minchars = 5

    if filepath:
        p = Path(filepath)
        if not p.exists(): return []
        data = p.read_bytes()

    if not data or not isinstance(data, bytes):
        return []

    rule_source = r"""
    rule GetStrings {
        strings:
            $s = /[\x20-\x7e]{""" + str(minchars) + r""",}/ ascii wide
        condition:
            $s
    }
    """

    try:
        rule = yara.compile(source=rule_source)
        matches = rule.match(data=data)
    except yara.Error:
        return []

    all_instances = []
    for match in matches:
        for string_match in match.strings:
            for instance in string_match.instances:
                all_instances.append({
                    'offset': instance.offset,
                    'data': instance.matched_data,
                    'length': len(instance.matched_data)
                })

    all_instances.sort(key=lambda x: x['offset'])

    strings = []
    last_end_offset = -1

    for inst in all_instances:
        current_start = inst['offset']
        current_end = current_start + inst['length']

        if current_start < last_end_offset:
            continue

        val = inst['data']
        decoded = None

        if b"\x00" in val:
            try:
                decoded = val.decode("utf-16le")
            except UnicodeDecodeError:
                pass

        if not decoded:
            decoded = val.decode("ascii", errors="ignore")

        if decoded:
            strings.append(decoded)
            last_end_offset = current_end

    if dedup:
        strings = list(set(strings))

    return strings

