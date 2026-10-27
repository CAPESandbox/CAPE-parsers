# Copyright (C) 2026 CAPE Sandbox Developers.
# This file is part of CAPE-parsers.
# See the file 'LICENSE' for copying permission.

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any
import importlib
import tempfile
from pathlib import Path

import pytest

from cape_parsers.utils import yara_wrapper as yara
from cape_parsers.utils.strings import extract_strings


def test_yara_wrapper_exception_hierarchy():
    """Verifies that custom and backend exceptions are catchable via yara.Error."""
    # Custom base error
    with pytest.raises(yara.Error):
        raise yara.YaraWrapperError("test error")

    # Custom syntax error
    with pytest.raises(yara.SyntaxError):
        raise yara.YaraWrapperSyntaxError("syntax error")

    with pytest.raises(yara.Error):
        raise yara.YaraWrapperSyntaxError("syntax error is an Error")

    # Timeout error
    with pytest.raises(yara.TimeoutError):
        raise yara.YaraWrapperTimeoutError("timeout")


def test_yara_x_string_match_instance_properties():
    """Tests all methods and properties on YaraXStringMatchInstance."""
    raw_data = b"ABCDEF123456"
    inst = yara.YaraXStringMatchInstance(
        offset=2,
        length=4,
        matched_data=raw_data[2:6],  # b"CDEF"
        xor_key=None,
        identifier="$test",
    )
    assert inst.offset == 2
    assert inst.matched_length == 4
    assert inst.matched_data == b"CDEF"
    assert inst.is_xor() is False
    assert inst.plaintext() == b"CDEF"
    assert int(inst) == 2
    assert len(inst) == 4
    assert bytes(inst) == b"CDEF"
    assert repr(inst)

    # Legacy tuple indexing compatibility: (offset, identifier, matched_data)
    assert inst[0] == 2
    assert inst[1] == "$test"
    assert inst[2] == b"CDEF"

    # XORed instance
    xor_key = 0x20
    xored_bytes = bytes(b ^ xor_key for b in b"CDEF")
    xor_inst = yara.YaraXStringMatchInstance(
        offset=10,
        length=4,
        matched_data=xored_bytes,
        xor_key=xor_key,
        identifier="$xored",
    )
    assert xor_inst.is_xor() is True
    assert xor_inst.plaintext() == b"CDEF"


def test_yara_x_string_match_properties():
    """Tests YaraXStringMatch properties."""
    inst1 = yara.YaraXStringMatchInstance(0, 3, b"foo", None, "$s")
    inst2 = yara.YaraXStringMatchInstance(10, 3, b"bar", 0x55, "$s")
    sm = yara.YaraXStringMatch(identifier="$s", instances=[inst1, inst2])

    assert sm.identifier == "$s"
    assert len(sm.instances) == 2
    assert sm.is_xor() is True
    assert repr(sm)


def test_yara_x_match_filtering_unmatched_patterns():
    """Tests YaraXMatch filtering out patterns with 0 occurrences."""
    # Mock a yara_x Rule object
    pattern_hit = SimpleNamespace(
        identifier="$hit",
        matches=[SimpleNamespace(offset=5, length=4, xor_key=None)],
    )
    pattern_miss = SimpleNamespace(
        identifier="$miss",
        matches=[],
    )
    fake_rule = SimpleNamespace(
        identifier="TestRule",
        namespace="default",
        tags=["trojan", "stealer"],
        metadata=[("author", "tester"), ("version", 1)],
        patterns=[pattern_hit, pattern_miss],
    )

    buf = b"01234TEST9999"
    match = yara.YaraXMatch(fake_rule, buf)

    assert match.rule == "TestRule"
    assert match.namespace == "default"
    assert match.tags == ["trojan", "stealer"]
    assert match.meta == {"author": "tester", "version": 1}

    # $miss MUST be filtered out so match.strings only contains patterns that matched
    assert len(match.strings) == 1
    assert match.strings[0].identifier == "$hit"
    assert len(match.strings[0].instances) == 1
    assert match.strings[0].instances[0].offset == 5
    assert match.strings[0].instances[0].matched_data == b"TEST"


def test_yara_x_rules_mocked_scanner_and_thread_safety():
    """Tests YaraXRules calling thread-safe scanner construction and concurrent matches."""
    class FakeScanResult:
        def __init__(self, data: bytes):
            self.matching_rules = [
                SimpleNamespace(
                    identifier="MockRule",
                    patterns=[
                        SimpleNamespace(
                            identifier="$a",
                            matches=[SimpleNamespace(offset=1, length=3, xor_key=None)],
                        )
                    ],
                )
            ]

    class FakeScanner:
        def __init__(self, rules):
            self.rules = rules
            self.timeout = None
            self.globals = {}

        def set_timeout(self, timeout):
            self.timeout = timeout

        def set_global(self, k, v):
            self.globals[k] = v

        def scan(self, data: bytes):
            return FakeScanResult(data)

    class FakeYaraXModule:
        Scanner = FakeScanner

    # Monkeypatch yara_wrapper's yara_x to test YaraXRules in isolation
    orig_yara_x = yara.yara_x
    try:
        yara.yara_x = FakeYaraXModule()
        fake_rules = SimpleNamespace()
        rules_wrapper = yara.YaraXRules(fake_rules)

        # Test scan with bytes
        hits = rules_wrapper.match(data=b"XABCZ")
        assert len(hits) == 1
        assert hits[0].rule == "MockRule"
        assert hits[0].strings[0].instances[0].matched_data == b"ABC"

        # Test scan with filepath
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"ZABCY")
            tf_path = tf.name

        try:
            file_hits = rules_wrapper.match(filepath=tf_path)
            assert len(file_hits) == 1
            assert file_hits[0].strings[0].instances[0].matched_data == b"ABC"
        finally:
            Path(tf_path).unlink(missing_ok=True)

        # Test concurrent scanning across multiple threads
        def worker(idx):
            data = f"#{idx}ABC#".encode()
            res = rules_wrapper.match(data=data)
            return len(res)

        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(worker, range(10)))
        assert all(r == 1 for r in results)

    finally:
        yara.yara_x = orig_yara_x


def test_real_backend_compile_and_match():
    """Tests compilation and matching using whatever backend is currently available."""
    rule_src = """
    rule TestSample
    {
        meta:
            description = "Unit test rule"
        strings:
            $str = "TARGET_STRING"
            $hex = { 11 22 33 44 }
        condition:
            any of them
    }
    """
    rules = yara.compile(source=rule_src)
    payload = b"\x00\x00TARGET_STRING\x00\x11\x22\x33\x44\x55"

    matches = rules.match(data=payload)
    assert len(matches) >= 1
    match = matches[0]

    assert match.rule == "TestSample"
    identifiers = [s.identifier for s in match.strings]
    assert "$str" in identifiers
    assert "$hex" in identifiers

    str_match = next(s for s in match.strings if s.identifier == "$str")
    assert str_match.instances[0].offset == 2
    assert str_match.instances[0].matched_data == b"TARGET_STRING"


def test_strings_extract_strings():
    """Verifies that cape_parsers.utils.strings.extract_strings works with yara_wrapper."""
    sample_buf = b"FirstAsciiString\x00\x00" + "WideUnicodeString".encode("utf-16le") + b"\x00\x00"
    extracted = extract_strings(data=sample_buf, minchars=5)
    assert len(extracted) >= 2
    assert any("FirstAsciiString" in w for w in extracted)
    assert any("WideUnicodeString" in w for w in extracted)


def _discover_parser_modules():
    import cape_parsers
    parsers_root = Path(cape_parsers.__file__).parent
    modules = []

    for subpkg in ["CAPE/core", "CAPE/community", "deprecated"]:
        pkg_path = parsers_root / subpkg
        if not pkg_path.exists():
            continue
        for py_path in sorted(pkg_path.glob("*.py")):
            if py_path.name.startswith("__"):
                continue
            mod_name = f"cape_parsers.{subpkg.replace('/', '.')}.{py_path.stem}"
            try:
                mod = importlib.import_module(mod_name)
                modules.append((mod_name, mod))
            except Exception:
                # Some modules might have optional missing deps (e.g. unicorn, blzpack)
                continue
    return modules


@pytest.mark.parametrize("mod_name,mod", _discover_parser_modules())
def test_all_parser_rules_compilation(mod_name: str, mod: Any):
    """Iterates through all parsers and verifies that every embedded YARA rule compiles."""
    rule_attrs = [
        "rule_source", "RULE_SOURCE", "yara_rule", "YARA_RULES",
        "RULE_SOURCE_KEY", "RULE_SOURCE_KEY_X64",
        "RULE_SOURCE_ENCODED_STRINGS", "RULE_SOURCE_ENCODED_STRINGS_X64",
        "RULE_SOURCE_LUMMA", "RULE_SOURCE_LUMMA_NEW_KEYS",
        "RULE_SOURCE_LUMMA_NEW_ENCRYPTED_C2", "RULE_SOURCE_AES_KEY",
    ]

    for attr in rule_attrs:
        src = getattr(mod, attr, None)
        if isinstance(src, str) and "rule " in src and "condition:" in src:
            try:
                compiled = yara.compile(source=src)
                assert compiled is not None
            except Exception as exc:
                pytest.fail(f"Failed to compile {attr} in {mod_name}: {exc}")
