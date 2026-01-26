from contextlib import suppress

try:
    from cape_parsers.utils.strings import extract_strings
except ImportError as e:
    print(f"Problem importing extract_strings: {e}")

import logging
log = logging.getLogger(__name__)


def extract_config(data: bytes):
    config = {}

    with suppress(Exception):
        if data[:2] == b"MZ":
            return

        header_data = data[:1024]
        lines = extract_strings(data=header_data, minchars=3, dedup=False)

        if len(lines) < 4:
            return None

        if '\\' in lines[2]:
            config.setdefault("raw", {})["directory"] = (lines[1].strip() + '\\' + lines[0].strip()).replace('  ', ' ')
            config.setdefault("raw", {})["inject_dll"] = lines[2].strip()
        if '.exe' in lines[3]:
            config.setdefault("raw", {})["exe_name"] = lines[3].strip()

        if config:
            config.setdefault("raw", config)
            return config

if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
