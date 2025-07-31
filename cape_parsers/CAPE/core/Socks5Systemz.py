import socket
from contextlib import suppress


def _is_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except Exception:
        return False


def extract_config(data):
    config_dict = {}
    with suppress(Exception):
        if data[:2] == b"MZ":
            return
        for line in data.decode().split("\n"):
            if _is_ip(line) and line not in config_dict.get("CNCs", []):
                config_dict["CNCs"].append(line)
            elif line and "\\" in line:
                config_dict.setdefault("Timestamp path", []).append(line)
            elif "." in line and "=" not in line and line not in config_dict["CNCs"]:
                config_dict.setdefault("raw", {}).setdefault("Dummy domain", []).append(line)
        return config_dict
