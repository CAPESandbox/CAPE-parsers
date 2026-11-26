# Key derivation and verification data: OALabs Research, "LimeRAT" (2023-08-17), Apache-2.0.
# https://github.com/OALabs/research/blob/master/_notebooks/2023-08-17-limerat.ipynb

import base64
import hashlib
import logging
import re
from contextlib import suppress
from urllib.parse import urlsplit

import dnfile
from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.clr.token import StringToken, Token

DESCRIPTION = "LimeRAT configuration parser"
AUTHOR = "BinaryBear"

log = logging.getLogger(__name__)

# LimeRAT keeps its settings as 15 literals in the settings type's .cctor, in this order.
SETTINGS_FIELDS = (
    "config_url",
    "encryption_key",
    "endof",
    "split",
    "exe",
    "usb",
    "pin",
    "anti",
    "drop",
    "path1",
    "path2",
    "btc_address",
    "downloader_once",
    "download_link",
    "delay",
)
FIELD_NAME_MAP = {
    "pastebin": "config_url",
    "host": "config_url",
    "key": "encryption_key",
    "encryptionkey": "encryption_key",
    "endof": "endof",
    "spl": "split",
    "split": "split",
    "exe": "exe",
    "usb": "usb",
    "pin": "pin",
    "anti": "anti",
    "drop": "drop",
    "path1": "path1",
    "path2": "path2",
    "btc": "btc_address",
    "btc_address": "btc_address",
    "downloaderonce": "downloader_once",
    "downloaderlink": "download_link",
    "download_link": "download_link",
    "delay": "delay",
}
FIELD_TABLE_INDEX = 0x04
ENDOF = "|'N'|"
SPL = "|'L'|"
URL_RE = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)
HOST_PORT_RE = re.compile(r"^(?:[A-Za-z0-9.-]{3,253}|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}$")


class _MethodBodyReader(CilMethodBodyReaderBase):
    def __init__(self, pe, row):
        self.pe = pe
        raw_data = getattr(pe, "__data__", None)
        self._data = memoryview(raw_data) if raw_data is not None else None
        self.offset = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n):
        if self._data is not None:
            if self.offset < 0 or self.offset >= len(self._data):
                return b""
            data = bytes(self._data[self.offset : self.offset + n])
        else:
            data = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += len(data)
        return data

    def tell(self):
        return self.offset

    def seek(self, offset):
        self.offset = offset
        return self.offset


def _read_user_string(pe, token):
    if not isinstance(token, StringToken):
        return None
    try:
        user_string = pe.net.user_strings.get(token.rid)
    except Exception:
        return None
    if user_string is None or user_string.value is None:
        return None
    return user_string.value


def _extract_named_settings(pe, instructions, values_by_idx):
    field_table = getattr(pe.net.mdtables, "Field", None)
    field_rows = getattr(field_table, "rows", None) if field_table is not None else None
    if not field_rows:
        return None

    named = {}
    for idx, value in values_by_idx.items():
        if value is None or idx + 1 >= len(instructions):
            continue
        next_ins = instructions[idx + 1]
        if next_ins.mnemonic != "stsfld":
            continue
        operand = next_ins.operand
        if not isinstance(operand, Token) or operand.table != FIELD_TABLE_INDEX:
            continue
        rid = operand.rid
        if rid < 1 or rid > len(field_rows):
            continue
        field_name = getattr(getattr(field_rows[rid - 1], "Name", None), "value", None)
        if not field_name:
            continue
        canonical = FIELD_NAME_MAP.get(field_name.lower())
        if canonical and canonical not in named:
            named[canonical] = value

    if "config_url" in named and "encryption_key" in named and len(named) >= 4:
        return {field: named.get(field, "") for field in SETTINGS_FIELDS}
    return None


def _settings_candidates(pe):
    """Yield candidate settings mappings from each .cctor method."""
    if not pe.net or not pe.net.user_strings or not pe.net.mdtables or not pe.net.mdtables.MethodDef:
        return

    for row in pe.net.mdtables.MethodDef:
        if not getattr(row, "Rva", 0):
            continue

        try:
            if not row.ImplFlags.miIL or row.Flags.mdAbstract or row.Flags.mdPinvokeImpl:
                continue
        except Exception:
            continue

        if getattr(getattr(row, "Name", None), "value", None) != ".cctor":
            continue

        try:
            body = CilMethodBody(_MethodBodyReader(pe, row))
        except Exception:
            continue

        instructions = body.instructions
        if not instructions or len(instructions) < 8:
            continue

        values = []
        values_by_idx = {}
        for idx, instruction in enumerate(instructions):
            if instruction.is_ldstr():
                val = _read_user_string(pe, instruction.operand)
                values.append(val)
                values_by_idx[idx] = val

        if len(values) < 4:
            continue

        yielded = False
        for anchor in range(2, len(values) - 1):
            if values[anchor] == ENDOF and values[anchor + 1] == SPL:
                block = values[anchor - 2 : anchor - 2 + len(SETTINGS_FIELDS)]
                if isinstance(block[0], str) and isinstance(block[1], str):
                    padded = [v if isinstance(v, str) else "" for v in block]
                    if len(padded) < len(SETTINGS_FIELDS):
                        padded.extend("" for _ in range(len(SETTINGS_FIELDS) - len(padded)))
                    yield dict(zip(SETTINGS_FIELDS, padded))
                    yielded = True

        if not yielded:
            named = _extract_named_settings(pe, instructions, values_by_idx)
            if named is not None:
                yield named


def _aes_key(encryption_key: str) -> bytes:
    digest = hashlib.md5(encryption_key.encode("utf-8")).digest()
    # The builder copies the MD5 digest over itself at offset 15 and leaves the last byte zero.
    return digest[:15] + digest + b"\x00"


def _is_valid_host_port(value: str) -> bool:
    if not HOST_PORT_RE.match(value):
        return False
    _, port_str = value.rsplit(":", 1)
    return 1 <= int(port_str) <= 65535


def _decrypt_config_url(encrypted_url: str, encryption_key: str, aes_key: bytes | None = None):
    try:
        ciphertext = base64.b64decode("".join(encrypted_url.split()), validate=True)
        if not ciphertext or len(ciphertext) % AES.block_size:
            return None
        key = aes_key if aes_key is not None else _aes_key(encryption_key)
        plaintext = Padding.unpad(
            AES.new(key, AES.MODE_ECB).decrypt(ciphertext),
            block_size=AES.block_size,
            style="pkcs7",
        )
        config_url = plaintext.decode("utf-8").strip()
    except Exception:
        return None

    if config_url and (URL_RE.match(config_url) or _is_valid_host_port(config_url)):
        return config_url
    return None


def _format_cnc(config_url: str):
    try:
        if URL_RE.match(config_url):
            parsed = urlsplit(config_url)
            if not parsed.hostname:
                return None
            default_ports = {"ftp": 21, "http": 80, "https": 443}
            port = parsed.port or default_ports.get(parsed.scheme.lower(), 80)
            host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
            uri = parsed.path or "/"
            if parsed.query:
                uri = f"{uri}?{parsed.query}"
            return f"{parsed.scheme.lower()}://{host}:{port}{uri}"
        if _is_valid_host_port(config_url):
            host, port = config_url.rsplit(":", 1)
            return f"tcp://{host}:{port}"
    except Exception:
        return None
    return None


def _as_bool(value: str) -> bool:
    return value.strip().lower() == "true"


def _as_int(value: str):
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return value


def extract_config(data: bytes):
    config = {}

    try:
        pe = dnfile.dnPE(data=data)
    except Exception:
        return config

    try:
        for settings in _settings_candidates(pe):
            aes_key = _aes_key(settings["encryption_key"])
            config_url = _decrypt_config_url(settings["config_url"], settings["encryption_key"], aes_key=aes_key)
            if not config_url:
                continue

            raw = {
                "config_url": config_url,
                "encryption_key": settings["encryption_key"],
                "endof": settings["endof"],
                "split": settings["split"],
                "exe": settings["exe"],
                "usb": _as_bool(settings["usb"]),
                "pin": _as_bool(settings["pin"]),
                "anti": _as_bool(settings["anti"]),
                "drop": _as_bool(settings["drop"]),
                "path1": settings["path1"],
                "path2": settings["path2"],
                "btc_address": settings["btc_address"],
                "downloader_once": _as_bool(settings["downloader_once"]),
                "download_link": settings["download_link"].strip(),
                "delay": _as_int(settings["delay"]),
                "config_url_type": "dead_drop" if URL_RE.match(config_url) else "direct",
            }

            config["cryptokey"] = aes_key.hex()
            config["cryptokey_type"] = "AES"
            config["raw"] = raw

            # LimeRAT downloads the final HOST:PORT list from this dead-drop URL at runtime.
            cnc = _format_cnc(config_url)
            if cnc:
                config["CNCs"] = [cnc]
            break
    except Exception:
        log.exception("LimeRAT config extraction failed")
        return {}
    finally:
        with suppress(Exception):
            pe.close()

    return config


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
