import argparse
import json
import logging
import os
import re
import struct
import sys

from typing import Any, Dict, Optional
from urllib.parse import urlparse

log = logging.getLogger(__name__)

"""
V1:
  [enc_config][config_len (LE u32)][MAGIC_V1]

V2:
  [enc_config][pdf_bytes?][pdf_len (LE u32)][config_len (LE u32)][MAGIC_V2]

enc_config:
  [IV (16)][AES-CBC ciphertext...], PKCS7 padding, UTF-8 JSON plaintext
"""

MAGIC_V1 = bytes([68, 67, 67, 70, 71, 1, 2, 3])  # "DCCFG\x01\x02\x03"
MAGIC_V2 = bytes([68, 67, 67, 70, 71, 2, 2, 3])  # "DCCFG\x02\x02\x03"

KEY = bytes([
    167, 59, 225, 148, 214, 40, 95, 192, 18, 142,
    74, 247, 99, 185, 13, 81, 232, 44, 118, 175,
    57, 133, 212, 27, 240, 110, 163, 87, 201, 20,
    139, 98
])


class PackResult(object):
    def __init__(self, version, config_json, pdf_bytes, magic_off):
        self.version = version
        self.config_json = config_json
        self.pdf_bytes = pdf_bytes
        self.magic_off = magic_off


def _hex_to_ascii_maybe(s: str) -> Optional[str]:
    if not isinstance(s, str):
        return None

    t = s.strip()
    if "\\x" in t:
        bytes_hex = re.findall(r"\\x([0-9a-fA-F]{2})", t)
        if bytes_hex:
            t = "".join(bytes_hex)

    t = re.sub(r"^0x", "", t, flags=re.IGNORECASE)
    t = re.sub(r"[^0-9a-fA-F]", "", t)
    if not t or (len(t) % 2) != 0:
        return None

    try:
        b = bytes.fromhex(t)
    except ValueError:
        return None

    try:
        decoded = b.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        decoded = b.decode("latin-1", errors="strict")

    printable_ratio = sum(32 <= ord(c) <= 126 or c in "\r\n\t" for c in decoded) / max(1, len(decoded))
    if printable_ratio < 0.85:
        return None

    return decoded.strip("\x00")


def add_ascii_email_field(cfg: Dict[str, Any], src_key: str = "Email", dst_key: str = "Email_ascii") -> Dict[str, Any]:
    """
    If cfg[src_key] is hex, decode to ASCII and set cfg[dst_key].
    Returns cfg (mutated).
    """
    v = cfg.get(src_key)
    if isinstance(v, str):
        decoded = _hex_to_ascii_maybe(v)
        if decoded:
            cfg[dst_key] = decoded
    return cfg


def bytes_match(haystack, offset, needle):
    if offset < 0 or offset + len(needle) > len(haystack):
        return False
    return haystack[offset:offset + len(needle)] == needle


def read_u32_le(buf, offset):
    if offset < 0 or offset + 4 > len(buf):
        return None
    return struct.unpack_from("<I", buf, offset)[0]


def pkcs7_unpad(padded, block_size=16):
    if not padded:
        raise ValueError("Empty plaintext")
    pad = padded[-1]
    if pad < 1 or pad > block_size:
        raise ValueError("Bad PKCS7 padding length")
    if padded[-pad:] != bytes([pad]) * pad:
        raise ValueError("Bad PKCS7 padding bytes")
    return padded[:-pad]


def decrypt_config_blob(enc, key):
    """
    Mirrors the C#:
      - first 16 bytes = IV
      - AES-CBC with PKCS7 padding
      - UTF-8 decode
    """
    if len(enc) < 17:
        log.debug("DocConnect: encrypted data too short (need IV + payload)")
        return None

    iv = enc[:16]
    ct = enc[16:]

    try:
        from Cryptodome.Cipher import AES
    except Exception:
        try:
            from Crypto.Cipher import AES
        except Exception:
            log.error("DocConnect: pycryptodome is not installed")
            return None

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt_padded = cipher.decrypt(ct)
    try:
        pt = pkcs7_unpad(pt_padded, 16)
        return pt.decode("utf-8")
    except Exception as e:
        log.debug("DocConnect: failed to unpad/decode decrypted config: %s", e)
        return None


def try_unpack_v2_at_magic(exe_bytes, magic_off, debug=False, verbose=False):
    if not bytes_match(exe_bytes, magic_off, MAGIC_V2):
        return None

    pdf_len_off = magic_off - 4
    if pdf_len_off < 0:
        return None

    pdf_len = read_u32_le(exe_bytes, pdf_len_off)
    if pdf_len is None:
        return None

    max_pdf = magic_off
    if pdf_len > max_pdf:
        return None

    cfg_len_off = pdf_len_off - pdf_len - 4
    if cfg_len_off < 0:
        return None

    cfg_len = read_u32_le(exe_bytes, cfg_len_off)
    if cfg_len is None:
        return None
    if cfg_len == 0 or cfg_len > cfg_len_off:
        return None

    cfg_start = cfg_len_off - cfg_len
    if cfg_start < 0:
        return None

    enc_cfg = exe_bytes[cfg_start:cfg_start + cfg_len]

    try:
        if debug:
            log.debug("V2 @0x%X pdf_len=%d cfg_len=%d cfg_start=0x%X", magic_off, pdf_len, cfg_len, cfg_start)
        config_json = decrypt_config_blob(enc_cfg, KEY)
        if not config_json:
            return None
    except Exception:
        return None

    pdf_bytes = None
    if pdf_len > 0:
        pdf_start = pdf_len_off - pdf_len
        if pdf_start < 0:
            return None
        pdf_bytes = exe_bytes[pdf_start:pdf_start + pdf_len]

    if verbose:
        log.info("Found V2 magic at 0x%X, decrypted OK", magic_off)
    return PackResult("v2", config_json, pdf_bytes, magic_off)


def try_unpack_v1_at_magic(exe_bytes, magic_off, debug=False, verbose=False):
    if not bytes_match(exe_bytes, magic_off, MAGIC_V1):
        return None

    cfg_len_off = magic_off - 4
    if cfg_len_off < 0:
        return None

    cfg_len = read_u32_le(exe_bytes, cfg_len_off)
    if cfg_len is None:
        return None

    max_cfg = magic_off
    if cfg_len == 0 or cfg_len > max_cfg:
        return None

    cfg_start = cfg_len_off - cfg_len
    if cfg_start < 0:
        return None

    enc_cfg = exe_bytes[cfg_start:cfg_start + cfg_len]

    try:
        if debug:
            log.debug("V1 @0x%X cfg_len=%d cfg_start=0x%X", magic_off, cfg_len, cfg_start)
        config_json = decrypt_config_blob(enc_cfg, KEY)
        if not config_json:
            return None
    except Exception:
        return None

    if verbose:
        log.info("Found V1 magic at 0x%X, decrypted OK", magic_off)
    return PackResult("v1", config_json, None, magic_off)


def iter_magic_hits_backwards(buf, magic, max_hits=200):
    """
    Yield offsets of 'magic' from last occurrence to earlier ones.
    """
    end = len(buf)
    for _ in range(max_hits):
        off = buf.rfind(magic, 0, end)
        if off == -1:
            return
        yield off
        end = off


def unpack_any(buf, debug=False, verbose=False):
    for off in iter_magic_hits_backwards(buf, MAGIC_V2):
        res = try_unpack_v2_at_magic(buf, off, debug=debug, verbose=verbose)
        if res is not None:
            return res

    for off in iter_magic_hits_backwards(buf, MAGIC_V1):
        res = try_unpack_v1_at_magic(buf, off, debug=debug, verbose=verbose)
        if res is not None:
            return res

    log.debug("DocConnect: decode failed for all magic candidates")
    return None


def extract_config(data: bytes) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}

    res = unpack_any(data, debug=False, verbose=False)
    if not res:
        return cfg

    try:
        config_obj = json.loads(res.config_json)
    except Exception:
        return {"raw": {"config_json": res.config_json}}

    if isinstance(config_obj, dict):
        add_ascii_email_field(config_obj)
        output: Dict[str, Any] = {}
        raw: Dict[str, Any] = dict(config_obj)

        cncs = []
        for endpoint_key in ("ApiBase", "HubUrl"):
            endpoint = config_obj.get(endpoint_key)
            if not isinstance(endpoint, str) or not endpoint:
                continue

            parsed = urlparse(endpoint)
            if parsed.scheme and parsed.netloc:
                cncs.append(endpoint)

        if cncs:
            output["CNCs"] = sorted(set(cncs))
            raw.pop("ApiBase", None)
            raw.pop("HubUrl", None)

        campaign = config_obj.get("OrganizationId")
        if isinstance(campaign, str) and campaign:
            output["campaign"] = campaign
            raw.pop("OrganizationId", None)

        if raw:
            output["raw"] = raw

        return output

    return {"raw": {"config_json": res.config_json}}


def main():
    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s: %(message)s")

    ap = argparse.ArgumentParser(description="Unpack + decrypt DCCFG config by finding MAGIC anywhere (no PE/cert logic).")
    ap.add_argument("binary", help="Path to the blob/binary")
    ap.add_argument("--outdir", default=".", help="Output directory (default: current dir)")
    ap.add_argument("--json-out", default="config.json", help="Output JSON filename (default: config.json)")
    ap.add_argument("--pdf-out", default="embedded.pdf", help="Output PDF filename if present (default: embedded.pdf)")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON if it parses")
    ap.add_argument("--print-json", action="store_true", help="Print decrypted JSON to stdout")
    ap.add_argument("--debug", action="store_true", help="Print per-candidate offsets/lengths")
    ap.add_argument("--cape", action="store_true", help="Return/log only extract_config() output")
    args = ap.parse_args()

    with open(args.binary, "rb") as f:
        buf = f.read()

    if args.cape:
        cfg = extract_config(buf)
        if args.pretty:
            log.info("%s", json.dumps(cfg, indent=2))
        else:
            log.info("%s", json.dumps(cfg))
        return 0

    res = unpack_any(buf, debug=args.debug, verbose=True)
    if not res:
        log.error("DocConnect: failed to unpack/decrypt configuration")
        return 1

    try:
        config_obj = json.loads(res.config_json)

        if isinstance(config_obj, dict):
            add_ascii_email_field(config_obj)

        config_text = json.dumps(config_obj, indent=2 if args.pretty else None)

    except Exception:
        config_text = res.config_json

    os.makedirs(args.outdir, exist_ok=True)

    json_path = os.path.join(args.outdir, args.json_out)
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(config_text)

    log.info("Unpacked payload: %s", res.version)
    log.info("Magic offset: 0x%X", res.magic_off)
    log.info("Wrote config JSON: %s", json_path)

    if res.pdf_bytes:
        pdf_path = os.path.join(args.outdir, args.pdf_out)
        with open(pdf_path, "wb") as f:
            f.write(res.pdf_bytes)
        log.info("Wrote embedded PDF: %s", pdf_path)
    else:
        log.info("No embedded PDF")

    if args.print_json:
        log.info("----- DECRYPTED CONFIG JSON -----\n%s", config_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
