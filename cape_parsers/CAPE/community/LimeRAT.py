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
from dncil.clr.token import StringToken

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
ENDOF = "|'N'|"
SPL = "|'L'|"
URL_RE = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)
HOST_PORT_RE = re.compile(r"^(?:[A-Za-z0-9.-]{3,253}|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}$")


class _MethodBodyReader(CilMethodBodyReaderBase):
    def __init__(self, pe, row):
        self.pe = pe
        self.offset = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n):
        data = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += len(data)
        return data

    def tell(self):
        return self.offset

    def seek(self, offset):
        self.offset = offset
        return self.offset


def _settings_candidates(pe):
    """Yield the 15 setting literals of each candidate .cctor method."""
    if not pe.net or not pe.net.user_strings or not pe.net.mdtables.MethodDef:
        return

    for row in pe.net.mdtables.MethodDef:
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

        if not body.instructions or len(body.instructions) < 20:
            continue

        ldstr = [instruction for instruction in body.instructions if str(instruction.opcode) == "ldstr"]
        if len(ldstr) != 15:
            continue

        values = []
        for instruction in ldstr:
            token = instruction.operand
            if not isinstance(token, StringToken):
                values = []
                break
            try:
                user_string = pe.net.user_strings.get(token.rid)
            except Exception:
                values = []
                break
            if user_string is None or user_string.value is None:
                values = []
                break
            values.append(user_string.value)

        if len(values) == 15 and values[2] == ENDOF and values[3] == SPL:
            yield values


def _aes_key(encryption_key: str) -> bytes:
    digest = hashlib.md5(encryption_key.encode("utf-8")).digest()
    # The builder copies the MD5 digest over itself at offset 15 and leaves the last byte zero.
    return digest[:15] + digest + b"\x00"


def _decrypt_config_url(encrypted_url: str, encryption_key: str):
    try:
        ciphertext = base64.b64decode("".join(encrypted_url.split()), validate=True)
        if not ciphertext or len(ciphertext) % AES.block_size:
            return None
        plaintext = Padding.unpad(
            AES.new(_aes_key(encryption_key), AES.MODE_ECB).decrypt(ciphertext),
            block_size=AES.block_size,
            style="pkcs7",
        )
        config_url = plaintext.decode("utf-8").strip()
    except Exception:
        return None

    if config_url and (URL_RE.match(config_url) or HOST_PORT_RE.match(config_url)):
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
        if HOST_PORT_RE.match(config_url):
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
        for values in _settings_candidates(pe):
            settings = dict(zip(SETTINGS_FIELDS, values))
            config_url = _decrypt_config_url(settings["config_url"], settings["encryption_key"])
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
                "config_url_type": "dead_drop",
            }

            config["cryptokey"] = _aes_key(settings["encryption_key"]).hex()
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
