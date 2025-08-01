import re
import sys
from pathlib import Path

"""
rule pony {
    meta:
        author = "adam"
        description = "Detect pony"

    strings:
        $s1 = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
        $s2 = "YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0"

    condition:
        $s1 and $s2
}
"""


gate_url = re.compile(b".*\\.php$")
exe_url = re.compile(b".*\\.exe$")
dll_url = re.compile(b".*\\.dll$")


def extract_config(memdump_path, read=False):
    if read:
        F = Path(memdump_path).read_bytes()
    else:
        F = memdump_path
    """
    # Get the   aPLib header + data
    buf = re.findall(r"aPLib .*PWDFILE", cData, re.DOTALL|re.MULTILINE)
    # Strip out the header
    if buf and len(buf[0]) > 200:
        cData = buf[0][200:]
    """
    config = {}
    artifacts_raw = {}

    start = F.find(b"YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0")
    if start:
        F = F[start - 600 : start + 500]

    output = re.findall(
        b"(https?://.[A-Za-z0-9-\\.\\_\\~\\:\\/\\?\\#\\[\\]\\@\\!\\$\\&'\\(\\)\\*\\+\\,\\;\\=]+(?:\\.php|\\.exe|\\.dll))", F
    )
    for url in output:
        try:
            if b"\x00" not in url:
                # url = self._check_valid_url(url)
                if url is None:
                    continue
                url = url.lower()
                if gate_url.match(url):
                    config.setdefault("CNCs", []).append(url.decode())
                elif exe_url.match(url) or dll_url.match(url):
                    artifacts_raw["downloads"].append(url.decode())
        except Exception as e:
            print(e, sys.exc_info(), "PONY")
    config["CNCs"] = list(set(config["controllers"]))
    config.setdefault("raw", {})["downloads"] = list(set(artifacts_raw["downloads"]))
    return config


if __name__ == "__main__":
    res = extract_config(sys.argv[1], read=True)
    print(res)
