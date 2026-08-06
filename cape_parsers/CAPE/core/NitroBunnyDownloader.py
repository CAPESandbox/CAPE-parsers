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
#
# ---------------------------------------------------------------------------
# Modified to support three observed code lineages and the RC4-encrypted
# config variant (e.g. a9be0114857faacd4d5781459b5f8305d07e48c2541f74885a9f194cfcb20456).
#
# The original $config pattern pinned three things that vary between builds:
#   1. a "mov ecx, imm32" immediately before the allocator call (absent in some builds)
#   2. "mov r8d, <size>" appearing BEFORE "lea rdx, <blob>" (the two are swapped in others)
#   3. "mov rcx, rax" encoded as 48 89 C1 (Clang); MSVC builds emit 48 8B C8
# $config1-3 below each pin one observed ordering of the size/lea/mov trio,
# bracketed by the surrounding calls. Every pattern is a fixed 29 bytes, so the
# size and lea positions come from CONFIG_OFFSETS instead of being searched for,
# and Python validates the blob structurally afterwards.
#
# Config layouts handled:
#   A. plaintext, UTF-16LE strings          (original)
#   B. RC4-encrypted, ASCII strings         (new)
#        blob[0:4]        = N (4-byte prefix + ciphertext length)
#        blob[4:N]        = RC4 ciphertext
#        blob[N:N+16]     = 16-byte RC4 key   (== the key used for C2 traffic)
#
# Layout B grammar (verified: consumes the plaintext exactly, no slack).
# Field->object mapping confirmed by tracing the sequential DWORD reader
# (sub_180026D60) in nb_config_decrypt_parse @0x180002930:
#     read#1 -> cfg+0x20 (magic)   read#2 -> cfg+0x24   read#3 -> cfg+0x28
#     read#4 -> cfg+0x00 (bool)    read#5 -> cfg+0x04   read#6 -> profile count
#
#   REC        := QWORD byte_len ; byte_len bytes, NUL-terminated ASCII
#                 (a REC may hold one token, or a whole CRLF-joined header set)
#   header     := DWORD magic (0x7CDF0A64)
#                 DWORD sleep_base        -> cfg+0x24
#                 DWORD jitter            -> cfg+0x28
#                 DWORD unk_c ; DWORD unk_d
#                 DWORD profile_count
#   profile    := DWORD unk_x ; DWORD unk_y
#                 DWORD n ; n * REC       (hosts)
#                 DWORD port
#                 DWORD n ; 2n * REC      (field-name pairs)
#                 DWORD unk_z
#                 DWORD n ; n * REC       (URIs)
#                 DWORD n ; n * REC       (token carrier names)
#                 DWORD n ; n * REC       (User-Agents)
#                 DWORD n ; n * REC       (header sets)
#
# nb_sleep_jitter @0x180035DE0 computes, with g an obfuscator global (0 observed):
#     sleep_ms = sleep_base*((g+46956)|0x2E)-46038) - rand() % ((jitter*sleep_base)/(2*(88-g)))
# i.e. sleep_base*920 - rand()%((jitter*sleep_base)/176). For 40/15 that is
# ~36800 ms, matching the 36-37 s beacon interval observed in the sandbox.
# ---------------------------------------------------------------------------

import logging
import re
import struct

import pefile
import yara

log = logging.getLogger(__name__)

DESCRIPTION = "NitroBunnyDownloader configuration parser."
AUTHOR = "enzok"

yara_rule = """
rule NitroBunnyDownloader
{
    meta:
        author = "enzok"
        description = "NitroBunnyDownloader Payload"
        cape_type = "NitroBunnyDownloader Payload"
        hash = "960e59200ec0a4b5fb3b44e6da763f5fec4092997975140797d4eec491de411b"
        hash2 = "a9be0114857faacd4d5781459b5f8305d07e48c2541f74885a9f194cfcb20456"
    strings:
        // call ; mov r8d,<size> ; lea rdx,<blob> ; mov rcx,rax ; mov r?,r? ; call
        $config1 = {E8 [3] 00 41 B8 ?? ?? 00 00 48 8D 15 [3] 00 48 (89 C1 | 8B C8) 4? 89 ?? E8 [3] 00}
        // call ; lea rdx,<blob> ; mov r8d,<size> ; mov rcx,rax ; mov r?,r? ; call
        $config2 = {E8 [3] 00 48 8D 15 [3] 00 41 B8 ?? ?? 00 00 48 (89 C1 | 8B C8) 4? 89 ?? E8 [3] 00}
        // call ; mov rcx,rax ; lea rdx,<blob> ; mov r8d,<size> ; mov r?,r? ; call
        $config3 = {E8 [3] 00 48 (8B C8 | 89 C1) 48 8D 15 [3] 00 41 B8 ?? ?? 00 00 4? 8B ?? E8 [3] 00}
    condition:
        uint16(0) == 0x5A4D and any of ($config*)
}
"""

yara_rules = yara.compile(source=yara_rule)

RC4_KEY_LEN = 16

CNC_SCHEMAS = {443: "https", 8443: "https"}

# (lea rdx offset, mov r8d imm32 offset) within each fixed 29-byte $config match
CONFIG_OFFSETS = {
    "$config1": (11, 7),  # call | 41 B8 <size> | 48 8D 15 <blob> | 48 89 C1  | 4? 89 ?? | call
    "$config2": (5, 14),  # call | 48 8D 15 <blob> | 41 B8 <size> | 48 89 C1  | 4? 89 ?? | call
    "$config3": (8, 17),  # call | 48 8B C8 | 48 8D 15 <blob> | 41 B8 <size>  | 4? 8B ?? | call
}


def yara_scan(raw_data):
    try:
        return yara_rules.match(data=raw_data)
    except Exception as e:
        log.error("yara scan failed: %s", e)
        return []


def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def _candidates(filebuf):
    """Yield (config_size, lea_offset) for every match, all three instruction orders."""
    for hit in yara_scan(filebuf):
        if hit.rule != "NitroBunnyDownloader":
            continue
        for item in hit.strings:
            offsets = CONFIG_OFFSETS.get(item.identifier)
            if not offsets:
                continue
            i_lea, i_sz = offsets
            for inst in item.instances:
                off = inst.offset
                size = struct.unpack_from("<I", filebuf, off + i_sz)[0]
                yield size, off + i_lea


def _read_blob(pe, filebuf, size, lea_off):
    """Resolve the lea's RIP-relative target to a blob of `size` bytes."""
    try:
        next_rva = pe.get_rva_from_offset(lea_off) + 7
        disp = struct.unpack_from("<i", filebuf, lea_off + 3)[0]
        return pe.get_data(next_rva + disp, size)
    except Exception:
        return None


def _read_utf16(data, off, nbytes):
    return data[off:off + nbytes].decode("utf-16le", errors="replace").rstrip("\x00"), off + nbytes


def _read_utf16_list(data, off, count):
    items = []
    for _ in range(count):
        ln, off = struct.unpack_from("<Q", data, off)[0], off + 8
        s, off = _read_utf16(data, off, ln)
        items.append(s)
    return items, off


def make_endpoints(cncs: list[str], port: int | None, uris: list[str]) -> list[str]:
    endpoints = []
    # HTTP is the only protocol this family speaks, so it is the default for an unknown port
    schema = CNC_SCHEMAS.get(port, "http")
    for cnc in cncs:
        base_url = f"{schema}://{cnc}"
        if port and port not in (80, 443):
            base_url += f":{port}"

        # with no URIs the host still has to be emitted, as a bare "<schema>://<host>/"
        for uri in uris or [""]:
            endpoints.append(f"{base_url}/{uri.lstrip('/')}")

    return endpoints


def parse_utf16_schema(data):
    """Original layout: port, n_c2, {qword len + UTF-16LE}, UA, headers, uris."""
    cfg, raw = {}, {}
    off = 0
    port, off = struct.unpack_from("<I", data, off)[0], off + 4
    if port not in (80, 443, 8080, 8443):
        return None
    num, off = struct.unpack_from("<I", data, off)[0], off + 4
    if not 1 <= num <= 16:
        return None
    cncs, off = _read_utf16_list(data, off, num)
    ln, off = struct.unpack_from("<Q", data, off)[0], off + 8
    cfg["user_agent"], off = _read_utf16(data, off, ln)
    num, off = struct.unpack_from("<I", data, off)[0], off + 4
    raw["http_header_items"], off = _read_utf16_list(data, off, num)
    num, off = struct.unpack_from("<I", data, off)[0], off + 4
    uris, off = _read_utf16_list(data, off, num)
    # port and the URI list are folded into the endpoints, so neither is kept separately
    cfg["CNCs"] = make_endpoints(cncs, port, uris)
    # NB: these two are NOT the layout-B sleep/jitter pair - observed values are
    # large and random-looking (e.g. 2261840800), so they are left unnamed.
    raw["unknown_1"], off = struct.unpack_from("<I", data, off)[0], off + 4
    raw["unknown_2"], off = struct.unpack_from("<I", data, off)[0], off + 4
    cfg["raw"] = raw
    return cfg


def _printable(b):
    # header-set records are CRLF-joined, so TAB/CR/LF are legal inside a record
    return all(32 <= c < 127 or c in (9, 10, 13) for c in b)


def _walk_records(data):
    """Yield (offset, string) for every 'QWORD length + NUL-terminated ASCII' record.

    A record holds either a single token (host, URI, User-Agent, header/cookie
    name) or an entire CRLF-joined header set. The exact grouping/nesting of the
    ASCII layout is not fully resolved, so records are recovered structurally and
    classified by shape below; structural DWORDs are returned separately.
    """
    off, items, fields = 0, [], []
    n = len(data)
    while off < n - 8:
        ln = struct.unpack_from("<Q", data, off)[0]
        if 2 <= ln <= 4096 and off + 8 + ln <= n:
            s = data[off + 8: off + 8 + ln]
            if len(s) > 1 and s[-1] == 0 and _printable(s[:-1]):
                items.append((off, s[:-1].decode()))
                off += 8 + ln
                continue
        fields.append((off, struct.unpack_from("<I", data, off)[0]))
        off += 4
    return items, fields


# nb_sleep_jitter constants, valid while the obfuscator global is 0 (as observed)
SLEEP_SCALE = 920


class _Reader:
    """Sequential reader mirroring sub_180026D60 / the REC reader."""

    MAX_COUNT = 512

    def __init__(self, data):
        self.d = data
        self.o = 0

    def dword(self):
        v = struct.unpack_from("<I", self.d, self.o)[0]
        self.o += 4
        return v

    def count(self):
        n = self.dword()
        if n > self.MAX_COUNT:
            raise ValueError(f"implausible count {n}")
        return n

    def rec(self):
        ln = struct.unpack_from("<Q", self.d, self.o)[0]
        self.o += 8
        if not 1 <= ln <= 0x10000 or self.o + ln > len(self.d):
            raise ValueError(f"bad record length {ln}")
        s = self.d[self.o:self.o + ln]
        self.o += ln
        if s[-1] != 0 or not _printable(s[:-1]):
            raise ValueError("record is not NUL-terminated ASCII")
        return s[:-1].decode()

    def rec_list(self, n):
        return [self.rec() for _ in range(n)]


def parse_profile_schema(data):
    """Strict walk of the layout-B grammar documented at the top of this file.

    Returns None unless the grammar consumes the plaintext exactly; that makes
    the whole parse self-validating, so a wrong key or a new layout fails loudly
    instead of yielding partial garbage.
    """
    try:
        r = _Reader(data)
        magic = r.dword()
        sleep_base = r.dword()
        jitter = r.dword()
        unk_c = r.dword()
        unk_d = r.dword()
        nprof = r.count()
        if not 1 <= nprof <= 16:
            return None

        profiles = []
        for _ in range(nprof):
            prefix = [r.dword(), r.dword()]
            hosts = r.rec_list(r.count())
            port = r.dword()
            names = r.rec_list(2 * r.count())
            unk_z = r.dword()
            uris = r.rec_list(r.count())
            carriers = r.rec_list(r.count())
            uas = r.rec_list(r.count())
            header_sets = r.rec_list(r.count())
            profiles.append({
                "hosts": hosts,
                "port": port,
                "field_names": names,
                "uris": uris,
                "token_carriers": carriers,
                "user_agents": uas,
                "header_sets": header_sets,
                "headers": [ln for hs in header_sets for ln in hs.split("\r\n") if ln],
                "unknown": {"prefix": prefix, "unk_z": unk_z},
            })

        if r.o != len(data):
            log.debug("profile schema left %d bytes unconsumed", len(data) - r.o)
            return None
    except Exception as e:
        log.debug("profile schema parse failed: %s", e)
        return None

    if not any(p["hosts"] for p in profiles):
        return None

    def flat(key):
        out = []
        for p in profiles:
            for v in p[key]:
                if v not in out:
                    out.append(v)
        return out

    # built per profile: hosts, port and URIs only pair up within the same profile
    endpoints = []
    for p in profiles:
        for endpoint in make_endpoints(p["hosts"], p["port"], p["uris"]):
            if endpoint not in endpoints:
                endpoints.append(endpoint)

    cfg = {"CNCs": endpoints}
    uas = flat("user_agents")
    cfg["user_agent"] = uas[0] if uas else None
    cfg["sleep"] = sleep_base
    cfg["jitter"] = jitter
    cfg["raw"] = {
        "magic": f"0x{magic:08X}",
        "sleep_base": sleep_base,
        "jitter": jitter,
        "sleep_ms": sleep_base * SLEEP_SCALE,
        "profile_count": nprof,
        "profiles": profiles,
        # flattened views; the URI list is omitted, it is folded into the endpoints
        "user_agents": uas,
        "http_header_items": flat("headers"),
        "token_carriers": flat("token_carriers"),
        "field_names": flat("field_names"),
        "unknown": {"unk_c": unk_c, "unk_d": unk_d},
    }
    return cfg


def parse_ascii_schema(data):
    """Loose fallback: recover records structurally and classify them by shape.

    Used when parse_profile_schema rejects the buffer (unknown build), so a new
    layout still yields the actionable indicators.
    """
    items, fields = _walk_records(data)
    if len(items) < 5:
        return None

    cfg, raw = {}, {}
    # a host is a dotted label (or bare IP) with no spaces and no leading slash
    host_re = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z]{2,}$|^\d{1,3}(\.\d{1,3}){3}$")

    cncs, uris, uas, headers, others = [], [], [], [], []
    for _, rec in items:
        lines = [ln for ln in rec.split("\r\n") if ln]
        if not lines:
            continue
        is_header_set = len(lines) > 1 or (": " in lines[0] and not lines[0].startswith("Mozilla/"))
        if is_header_set:
            for ln in lines:
                if ln not in headers:
                    headers.append(ln)
            continue
        s = lines[0]
        if s.startswith("Mozilla/"):
            uas.append(s)
        elif s.startswith("/"):
            uris.append(s)
        elif host_re.match(s):
            cncs.append(s)
        else:
            others.append(s)

    if not cncs:
        return None
    ports = [v for _, v in fields if v in (80, 443, 8080, 8443)]
    port = ports[0] if ports else None
    cfg["CNCs"] = make_endpoints(cncs, port, uris)
    cfg["user_agent"] = uas[0] if uas else None
    raw["port"] = port
    raw["user_agents"] = uas
    raw["uri_list"] = uris
    raw["http_header_items"] = headers
    # header/cookie names the implant hides its session token in
    raw["token_carriers"] = others
    raw["structural_dwords"] = [v for _, v in fields[:12]]
    cfg["raw"] = raw
    return cfg


def extract_config(filebuf):
    try:
        pe = pefile.PE(data=filebuf, fast_load=True)
    except Exception:
        return None

    for size, lea_off in _candidates(filebuf):
        if not 0x40 <= size <= 0x100000:
            continue
        blob = _read_blob(pe, filebuf, size, lea_off)
        if not blob or len(blob) != size:
            continue

        # --- layout B: RC4-encrypted (length prefix + ciphertext + trailing key)
        n = struct.unpack_from("<I", blob, 0)[0]
        if n and size == n + RC4_KEY_LEN:
            key = blob[n:n + RC4_KEY_LEN]
            plain = rc4(key, blob[4:n])
            cfg = parse_profile_schema(plain) or parse_ascii_schema(plain)
            if cfg:
                # the config key is also the key used for C2 request/response bodies
                cfg["cryptokey_type"] = "RC4"
                cfg["cryptokey"] = key.hex()
                cfg["raw"]["blob_size"] = size
                return cfg

        # --- layout A: plaintext UTF-16LE
        cfg = parse_utf16_schema(blob)
        if cfg:
            cfg["raw"]["blob_size"] = size
            return cfg

        # plaintext, ASCII profile layout
        cfg = parse_profile_schema(blob) or parse_ascii_schema(blob)
        if cfg:
            cfg["raw"]["blob_size"] = size
            return cfg

    return None


if __name__ == "__main__":
    import json
    import sys

    with open(sys.argv[1], "rb") as f:
        out = extract_config(f.read())
    print(json.dumps(out, indent=2) if out else "None")
