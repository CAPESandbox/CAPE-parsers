from contextlib import suppress

import logging
log = logging.getLogger(__name__)


def extract_config(data):
    config = {}
    with suppress(Exception):
        if data[:2] == b"MZ":
            return
        for line in data.decode().split("\n"):
            log.info(line)
            if 'http://' in line:
                config.setdefault("CNCs", []).append(line)
        if config:
            return config
