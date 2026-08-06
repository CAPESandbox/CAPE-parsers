import hashlib

from cape_parsers.CAPE.core.AxolotlLoader import extract_config


def test_axolotlloader_906035b6092b2ce1290c566f590e88f1b960b25c6d987f46a3d99cca5b05ee9d():
    with open("tests/data/malware/906035b6092b2ce1290c566f590e88f1b960b25c6d987f46a3d99cca5b05ee9d", "rb") as data:
        conf = extract_config(data.read())
        conf["dump_files"]["payload"] = hashlib.sha256(conf["dump_files"]["payload"]).hexdigest()
        assert conf == {
            "CNCs": ["https://www.digitalpoint.com:443/members/documentpublisher.1139897/"],
            "campaign": "30af8bb5-c090-4acf-bb56-57ff09ca98c3",
            "raw": {"init_uri": "/api/init/30af8bb5-c090-4acf-bb56-57ff09ca98c3", "deaddrop_marker": "-=("},
            "cryptokey": "7773795261585749",
            "cryptokey_type": "XOR",
            "dump_files": {"payload": "6d17a9b9c75d89f9ff40f2b081fd193dd8591347a2a367ca369ef1e19d6dc15a"},
        }
