import os
import importlib
import glob
from pathlib import Path
import inspect
import pkgutil
import logging
from contextlib import suppress
from types import ModuleType
from typing import Dict, Tuple

PARSERS_ROOT = Path(__file__).absolute().parent
log = logging.getLogger()


def load_cape_parsers(load: str = "all", exclude_parsers: list = []):
    """
    load: all, core, community
    exclude_parsers: [names of parsers that will be ignored]
    """
    versions = {
        "cape": "core",
        "community": "community",
    }

    cape_parsers = {}
    CAPE_DECODERS = {
        "cape": [os.path.basename(decoder)[:-3] for decoder in glob.glob(os.path.join(PARSERS_ROOT, "CAPE", "core", "[!_]*.py"))],
        "community": [
            os.path.basename(decoder)[:-3] for decoder in glob.glob(os.path.join(PARSERS_ROOT, "CAPE", "community", "[!_]*.py"))
        ],
    }

    for version, names in CAPE_DECODERS.items():
        if load != "all" and version != load:
            continue
        for name in names:
            try:
                # The name of the module must match what's given as the cape_type for yara
                # hits with the " Config", " Payload", or " Loader" ending removed and with  spaces replaced with underscores.
                # For example, a cape_type of "Emotet Payload" would trigger a config parser named "Emotet.py".
                if name in exclude_parsers:
                    continue
                cape_parsers[name.replace("_", " ")] = importlib.import_module(f"cape_parsers.CAPE.{versions[version]}.{name}")
                # PARSERS_TAGS[name.replace("_", " ")] = versions[version]
            except (ImportError, IndexError, AttributeError) as e:
                print(f"CAPE parser: No module named {name} - {e}")
            except SyntaxError as e:
                print(f"CAPE parser: Fix your code in {name} - {e}")
            except Exception as e:
                print(f"CAPE parser: Fix your code in {name} - {e}")
    return cape_parsers


def load_mwcp_parsers() -> Tuple[Dict[str, str], ModuleType]:
    HAVE_MWCP = False
    with suppress(ImportError):
        # We do not install this by default
        import mwcp

        HAVE_MWCP = True

    if not HAVE_MWCP:
        return {}, False

    logging.getLogger("mwcp").setLevel(logging.CRITICAL)
    mwcp.register_parser_directory(os.path.join(PARSERS_ROOT, "mwcp"))
    _malware_parsers = {block.name.rsplit(".", 1)[-1]: block.name for block in mwcp.get_parser_descriptions(config_only=False)}
    if "MWCP_TEST" not in _malware_parsers:
        return {}, mwcp
    return _malware_parsers, mwcp


def _malduck_load_decoders():

    malduck_modules = {}
    malduck_decoders = os.path.join("parsers", "malduck")
    decoders = [os.path.basename(decoder)[:-3] for decoder in glob.glob(f"{malduck_decoders}/[!_]*.py")]

    for name in decoders:
        try:
            malduck_modules[name] = importlib.import_module(f"cape_parsers.malduck.{name}")
        except (ImportError, IndexError) as e:
            print(f"malduck parser: No module named {name} - {e}")

    return malduck_modules


"""
def load_malduck_parsers():
    HAVE_MALDUCK = False
    with suppress(ImportError):
        from malduck.extractor import ExtractManager, ExtractorModules
        from malduck.extractor.extractor import Extractor
        from malduck.yara import Yara
        from lib.cuckoo.common.load_extra_modules import malduck_load_decoders
        HAVE_MALDUCK = True

    if not HAVE_MALDUCK:
        return {}

    malduck_modules = {}
    # from malduck.extractor.loaders import load_modules
    malduck_rules = Yara.__new__(Yara)
    malduck_modules = ExtractorModules.__new__(ExtractorModules)
    # tmp_modules = load_modules(os.path.join(CUCKOO_ROOT, process_cfg.malduck.modules_path))
    # malduck_modules_names = dict((k.rsplit(".", 1)[-1], v) for k, v in tmp_modules.items())
    malduck_modules_names = malduck_load_decoders(PARSERS_ROOT)
    malduck_modules.extractors = Extractor.__subclasses__()
    HAVE_MALDUCK = True
    # del tmp_modules
    if "test_malduck" not in malduck_modules_names:
        return {}
    return malduck_modules
"""


def load_malwareconfig_parsers() -> Tuple[bool, dict, ModuleType]:
    try:
        from malwareconfig import fileparser
        from malwareconfig.modules import __decoders__

        ratdecoders_local_modules = load_ratdecoders_parsers()
        if ratdecoders_local_modules:
            __decoders__.update(ratdecoders_local_modules)
        if "TestRats" not in __decoders__:
            return False, False, False
        return True, __decoders__, fileparser
    except ImportError:
        log.info("Missed RATDecoders -> poetry run pip install malwareconfig")
    except Exception as e:
        log.exception(e)
    return False, False, False


def load_ratdecoders_parsers():
    dec_modules = {}
    HAVE_MLW_CONFIGS = False
    with suppress(ImportError):
        # We do not install this by default as is outdated now, but if installed will be imported
        from malwareconfig.common import Decoder

        HAVE_MLW_CONFIGS = True

    if not HAVE_MLW_CONFIGS:
        return dec_modules

    # Walk recursively through all modules and packages.
    for loader, module_name, ispkg in pkgutil.walk_packages("cape_parsers.RATDecoders."):
        # If current item is a package, skip.
        if ispkg:
            continue
        # Try to import the module, otherwise skip.
        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            print(f"Unable to import Module {module_name}: {e}")
            continue
        for mod_name, mod_object in inspect.getmembers(module):
            if inspect.isclass(mod_object) and issubclass(mod_object, Decoder) and mod_object is not Decoder:
                dec_modules[mod_object.decoder_name] = dict(
                    obj=mod_object,
                    decoder_name=mod_object.decoder_name,
                    decoder_description=mod_object.decoder_description,
                    decoder_version=mod_object.decoder_version,
                    decoder_author=mod_object.decoder_author,
                )
    return dec_modules
