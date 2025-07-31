import importlib.util
import sys
import os

from rat_king_parser.rkp import RATConfigParser

HAVE_ASYNCRAT_COMMON = False
module_file_path = "/opt/CAPEv2/data/asyncrat_common.py"
if os.path.exists(module_file_path):
    try:
        module_name = os.path.basename(module_file_path).replace(".py", "")
        spec = importlib.util.spec_from_file_location(module_name, module_file_path)
        asyncrat_common = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = asyncrat_common
        spec.loader.exec_module(asyncrat_common)
        HAVE_ASYNCRAT_COMMON = True
    except Exception as e:
        print("Error loading asyncrat_common.py", e)


def extract_config(data: bytes):
    config = RATConfigParser(data=data, remap_config=True).report.get("config", {})
    if config and HAVE_ASYNCRAT_COMMON:
        config = asyncrat_common.convert_config(config)

    return config


if __name__ == "__main__":
    data = open(sys.argv[1], "rb").read()
    print(extract_config(data))
