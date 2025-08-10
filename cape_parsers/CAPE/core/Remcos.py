# This file is part of CAPE Sandbox - https://github.com/ctxis/CAPE
# See the file 'docs/LICENSE' for copying permission.
#
# This decoder is based on:
# Decryptor POC for Remcos RAT version 2.7.1 and earlier
# By Talos July 2018 - https://github.com/Cisco-Talos/remcos-decoder
# Updates based on work presented here https://gist.github.com/sysopfb/11e6fb8c1377f13ebab09ab717026c87
# Updates November 2024 by ClaudioWayne based on Elastic Security Labs: https://www.elastic.co/security-labs/dissecting-remcos-rat-part-one

DESCRIPTION = "Remcos config extractor."
AUTHOR = "threathive,sysopfb,kevoreilly"

import base64
import logging
import re
import string
from collections import OrderedDict
from contextlib import suppress

import pefile
from Cryptodome.Cipher import ARC4

# From JPCERT
FLAG = {b"\x00": "Disable", b"\x01": "Enable"}

# From JPCERT and Elastic Security Labs
idx_list = {
    0: "Host:Port:Password",  # String containing "domain:port:enable_tls" separated by the "\x1e" characte
    1: "Botnet",  # Name of the botnet
    2: "Connect interval",  # Interval in second between connection attempt to C2
    3: "Install flag",  # Install REMCOS on the machine host
    4: "Setup HKCU\\Run",  # Enable setup of the persistence in the registry
    5: "Setup HKLM\\Run",  # Enable setup of the persistence in the registry
    6: "Setup HKLM\\Explorer\\Run",
    7: "Keylog file max size",  # Maximum size of the keylogging data before rotation
    8: "Setup HKLM\\Explorer\\Run",  # Enable setup of the persistence in the registry
    9: "Install parent directory",  # Parent directory of the install folder. Integer mapped to an hardcoded path
    10: "Install filename",  # Name of the REMCOS binary once installed
    11: "Startup value",
    12: "Hide file",  # Enable super hiding the install directory and binary as well as setting them to read only
    13: "Process injection flag",  # 	Enable running the malware injected in another process
    14: "Mutex",  # String used as the malware mutex and registry key
    15: "Keylogger mode",  # Set keylogging capability. Keylogging mode, 0 = disabled, 1 = keylogging everything, 2 = keylogging specific window(s)
    16: "Keylogger parent directory",  # Parent directory of the keylogging folder. Integer mapped to an hardcoded path
    17: "Keylogger filename",  # Filename of the keylogged data
    18: "Keylog crypt",  # Enable encryption RC4 of the keylogger data file
    19: "Hide keylog file",  # Enable super hiding of the keylogger data file
    20: "Screenshot flag",  # Enable screen recording capability
    21: "Screenshot time",  # The time interval in minute for capturing each screenshot
    22: "Take Screenshot option",  # Enable screen recording for specific window names
    23: "Take screenshot title",  # String containing window names separated by the ";" character
    24: "Take screenshot time",  # s The time interval in second for capturing each screenshot when a specific window name is found in the current foreground window title
    25: "Screenshot parent directory",  # Parent directory of the screenshot folder. Integer mapped to an hardcoded path
    26: "Screenshot folder",  # Name of the screenshot folder
    27: "Screenshot crypt flag",  # Enable encryption of screenshots
    28: "Mouse option",
    29: "Unknown29",
    30: "Delete file",
    31: "Unknown31",
    32: "Unknown32",
    33: "Unknown33",
    34: "Unknown34",
    35: "Audio recording flag",  # Enable audio recording capability
    36: "Audio record time",  # Duration in second of each audio recording
    37: "Audio parent directory",  # Parent directory of the audio recording folder. Integer mapped to an hardcoded path
    38: "Audio folder",  # Name of the audio recording folder
    39: "Disable UAC flage",  # Disable UAC in the registry
    40: "Logging mode",  # Set logging mode: 0 = disabled, 1 = minimized in tray, 2 = console logging
    41: "Connect delay",  # Delay in second before the first connection attempt to the C2
    42: "Keylogger specific window names",  # String containing window names separated by the ";"" character
    43: "Browser cleaning on startup flag",  # Enable cleaning web browsers cookies and logins on REMCOS startup
    44: "Browser cleaning only for the first run flag",  # Enable web browsers cleaning only on the first run of Remcos
    45: "Browser cleaning sleep time in minutes",  # Sleep time in minute before cleaning the web browsers
    46: "UAC bypass flag",  # Enable UAC bypass capability
    47: "Unkown47",
    48: "Install directory",  # Name of the install directory
    49: "Keylogger root directory",  # Name of the keylogger directory
    50: "Watchdog flag",  # Enable watchdog capability
    51: "Unknown51",
    52: "License",  # License serial
    53: "Screenshot mouse drawing flag",  # Enable drawing the mouse on each screenshot
    54: "TLS raw certificate (base64)",  # Certificate in raw format used with tls enabled C2 communication
    55: "TLS key (base64)",  # Key of the certificate
    56: "TLS raw peer certificate (base64)",  # C2 public certificate in raw format
    57: "TLS client private key (base64)",
    58: "TLS server certificate (base64)",
    59: "Unknown59",
    60: "Unknown60",
    61: "Unknown61",
    62: "Unknown62",
    63: "Unknown63",
    64: "Unknown64",
    65: "Unknown65",
    66: "Unknown66",
}

# From JPCERT and Elastic Security Labs
setup_list = {
    0: "%Temp%",
    1: "<CurrentMalwareDirectory>",
    2: "%SystemDrive%",
    3: "%WinDir%",
    4: "%WinDir%//SysWOW64]",
    5: "%ProgramFiles%",
    6: "%AppData%",
    7: "%UserProfile%",
    8: "%ProgramData%",
}

utf_16_string_list = [
    "Keylogger specific window names",
    "Install filename",
    "Install directory",
    "Startup value",
    "Keylogger filename",
    "Take screenshot title",
    "Keylogger root directory",
]
logger = logging.getLogger(__name__)


def get_rsrc(pe):
    ret = []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return ret

    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        name = str(resource_type.name if resource_type.name is not None else pefile.RESOURCE_TYPE.get(resource_type.struct.Id))
        if hasattr(resource_type, "directory"):
            for resource_id in resource_type.directory.entries:
                if hasattr(resource_id, "directory"):
                    for resource_lang in resource_id.directory.entries:
                        data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                        ret.append((name, data, resource_lang.data.struct.Size, resource_type))

    return ret


def get_strings(data, min=4):
    result = ""
    for c in data:
        if chr(c) in string.printable:
            result += chr(c)
            continue
        if len(result) >= min:
            yield result
        result = ""
    if len(result) >= min:
        yield result


def check_version(filedata):
    s = ""
    # find strings in binary file
    slist = get_strings(filedata)

    # find and extract version string e.g. "2.0.5 Pro", "1.7 Free" or "1.7 Light"
    for s in slist:
        if bool(re.search(r"^\d+\.\d+(\.\d+)?\s+\w+$", s)):
            return s
    return ""


def extract_config(filebuf):
    config = {}

    try:
        pe = pefile.PE(data=filebuf)
        blob = False
        ResourceData = get_rsrc(pe)
        for rsrc in ResourceData:
            if rsrc[0] in ("RT_RCDATA", "SETTINGS"):
                blob = rsrc[1]
                break

        if blob:
            keylen = blob[0]
            key = blob[1 : keylen + 1]
            decrypted_data = ARC4.new(key).decrypt(blob[keylen + 1 :])
            p_data = OrderedDict()
            config["version"] = check_version(filebuf)

            configs = re.split(rb"\|\x1e\x1e\x1f\|", decrypted_data)

            for i, cont in enumerate(configs):
                if cont in (b"\x00", b"\x01"):
                    p_data[idx_list[i]] = FLAG[cont]
                elif i in (9, 16, 25, 37):
                    # observed config values in bytes instead of ascii
                    if cont[0] > 8:
                        p_data[idx_list[i]] = setup_list[int(chr(cont[0]))]
                    else:
                        p_data[idx_list[i]] = setup_list[cont[0]]
                elif i in (54, 55, 56, 57, 58):
                    p_data[idx_list[i]] = base64.b64encode(cont)
                elif i == 0:
                    # various separators have been observed
                    separator = next((x for x in (b"|", b"\x1e", b"\xff\xff\xff\xff") if x in cont))
                    host, port, password = cont.split(separator, 1)[0].split(b":")
                    config["CNCs"] = [f"tcp://{host.decode()}:{port.decode()}"]
                    p_data["Password"] = password.decode()
                else:
                    p_data[idx_list[i]] = cont

            for k, v in p_data.items():
                if k in utf_16_string_list:
                    v = v.decode("utf16").strip("\00") if isinstance(v, bytes) else v
                if isinstance(v, bytes):
                    with suppress(Exception):
                        v = v.decoed()
                config.setdefault("raw", {})[k] = v

    except Exception as e:
        logger.error("Caught an exception: %s", str(e))

    return config


if __name__ == "__main__":
    import sys

    print(extract_config(open(sys.argv[1], "rb").read()))
