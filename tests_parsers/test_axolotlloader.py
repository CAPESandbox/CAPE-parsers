import hashlib

from cape_parsers.CAPE.core.AxolotlLoader import extract_config


def test_axolotlloader_906035b6092b2ce1290c566f590e88f1b960b25c6d987f46a3d99cca5b05ee9d():
    with open("tests/data/malware/906035b6092b2ce1290c566f590e88f1b960b25c6d987f46a3d99cca5b05ee9d", "rb") as data:
        conf = extract_config(data.read())
        conf["dump_files"]["payload"] = hashlib.sha256(conf["dump_files"]["payload"]).hexdigest()
        assert conf == {"dump_files": {"payload": "0b9f4cd18d33f562ab3fe97add60c4978838057a859ffa5c4d71472778e9efe1"}}
