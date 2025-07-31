# Copyright (C) 2019 Kevin O'Reilly (kevoreilly@gmail.com)
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

import struct
import logging

import pefile
import yara

DESCRIPTION = "Azorult configuration parser."
AUTHOR = "kevoreilly"

YARA_RULES = """
rule Azorult
{
    meta:
        author = "kevoreilly"
        description = "Azorult Payload"
        cape_type = "Azorult Payload"
    strings:
        $ref_c2 = {6A 00 6A 00 6A 00 6A 00 68 ?? ?? ?? ?? FF 55 F0 8B D8 C7 47 10 ?? ?? ?? ?? 90 C7 45 B0 C0 C6 2D 00 6A 04 8D 45 B0 50 6A 06 53 FF 55 D4}
    condition:
        uint16(0) == 0x5A4D and all of them
}
"""

rules = yara.compile(source=YARA_RULES)
log = logging.getLogger()


def extract_config(filebuf):
    pe = pefile.PE(data=filebuf, fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    for match in rules.match(data=filebuf):
        for block in match.strings:
            for instance in block.instances:
                try:
                    cnc_offset = struct.unpack("i", instance.matched_data[21:25])[0]
                    cnc = pe.get_data(cnc_offset - image_base, 32).split(b"\x00")[0]
                    if cnc:
                        if not cnc.startswith(b"http"):
                            cnc = b"http://" + cnc
                        return {"CNCs": [cnc.decode()]}
                except Exception as e:
                    log.error("Error parsing Azorult config: %s", e)
    return {}


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
