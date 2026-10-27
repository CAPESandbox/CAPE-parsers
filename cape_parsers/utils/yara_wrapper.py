# Copyright (C) 2026 CAPE Sandbox Developers.
# This file is part of CAPE-parsers.
# See the file 'LICENSE' for copying permission.

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Union

log = logging.getLogger(__name__)

# Backend detection
try:
    import yara_x

    HAVE_YARA_X = True
except ImportError:
    yara_x = None
    HAVE_YARA_X = False

try:
    import yara as _yara

    HAVE_YARA = True
except ImportError:
    _yara = None
    HAVE_YARA = False


class YaraWrapperError(Exception):
    """Base exception class for yara_wrapper."""


class YaraWrapperSyntaxError(YaraWrapperError):
    """Syntax error exception class for yara_wrapper."""


class YaraWrapperTimeoutError(YaraWrapperError):
    """Timeout error exception class for yara_wrapper."""


# Dynamic error tuples so `except yara.Error:` and `except yara.SyntaxError:`
# work transparently whether yara-python, yara-x, or both are installed.
_error_types: List[type] = [YaraWrapperError]
_syntax_error_types: List[type] = [YaraWrapperSyntaxError]
_timeout_error_types: List[type] = [YaraWrapperTimeoutError]

if HAVE_YARA and _yara is not None:
    if hasattr(_yara, "Error"):
        _error_types.append(_yara.Error)
    if hasattr(_yara, "SyntaxError"):
        _syntax_error_types.append(_yara.SyntaxError)
    if hasattr(_yara, "TimeoutError"):
        _timeout_error_types.append(_yara.TimeoutError)

if HAVE_YARA_X and yara_x is not None:
    if hasattr(yara_x, "CompileError"):
        _error_types.append(yara_x.CompileError)
        _syntax_error_types.append(yara_x.CompileError)
    if hasattr(yara_x, "ScanError"):
        _error_types.append(yara_x.ScanError)
    if hasattr(yara_x, "TimeoutError"):
        _error_types.append(yara_x.TimeoutError)
        _timeout_error_types.append(yara_x.TimeoutError)

Error = tuple(_error_types)
SyntaxError = tuple(_syntax_error_types)
TimeoutError = tuple(_timeout_error_types)


class YaraXStringMatchInstance:
    """Emulates yara-python StringMatchInstance using yara_x match data."""

    __slots__ = ("offset", "matched_length", "matched_data", "xor_key", "_identifier")

    def __init__(
        self,
        offset: int,
        length: int,
        matched_data: bytes,
        xor_key: Optional[int] = None,
        identifier: str = "",
    ):
        self.offset: int = int(offset)
        self.matched_length: int = int(length)
        self.matched_data: bytes = matched_data
        self.xor_key: Optional[int] = xor_key
        self._identifier: str = identifier

    def is_xor(self) -> bool:
        """Returns True if this match was XOR-encoded."""
        return self.xor_key is not None

    def plaintext(self) -> bytes:
        """Returns un-XORed plaintext bytes if XORed, otherwise matched_data."""
        if self.xor_key is not None:
            return bytes(b ^ self.xor_key for b in self.matched_data)
        return self.matched_data

    def __getitem__(self, idx: int) -> Any:
        """Legacy tuple compatibility: (offset, identifier, matched_data)."""
        return (self.offset, self._identifier, self.matched_data)[idx]

    def __int__(self) -> int:
        return self.offset

    def __len__(self) -> int:
        return self.matched_length

    def __bytes__(self) -> bytes:
        return self.matched_data

    def __repr__(self) -> str:
        return (
            f"<YaraXStringMatchInstance offset={self.offset} "
            f"length={self.matched_length} xor_key={self.xor_key}>"
        )


class YaraXStringMatch:
    """Emulates yara-python StringMatch using yara_x pattern data."""

    __slots__ = ("identifier", "instances")

    def __init__(self, identifier: str, instances: List[YaraXStringMatchInstance]):
        self.identifier: str = identifier
        self.instances: List[YaraXStringMatchInstance] = instances

    def is_xor(self) -> bool:
        return any(inst.is_xor() for inst in self.instances)

    def __repr__(self) -> str:
        return f"<YaraXStringMatch identifier='{self.identifier}' instances={len(self.instances)}>"


class YaraXMatch:
    """Emulates yara-python Match using yara_x Rule data."""

    __slots__ = ("rule", "namespace", "tags", "meta", "strings")

    def __init__(self, rule_obj: Any, data: bytes):
        self.rule: str = getattr(rule_obj, "identifier", str(rule_obj))
        self.namespace: str = getattr(rule_obj, "namespace", "default")
        self.tags: List[str] = list(getattr(rule_obj, "tags", ()))

        raw_meta = getattr(rule_obj, "metadata", ())
        if isinstance(raw_meta, dict):
            self.meta: Dict[str, Any] = dict(raw_meta)
        elif isinstance(raw_meta, (list, tuple)):
            self.meta = dict(raw_meta)
        else:
            self.meta = {}

        strings_list: List[YaraXStringMatch] = []
        data_len = len(data) if data is not None else 0

        # Only include patterns that actually matched, matching yara-python semantics
        for pattern in getattr(rule_obj, "patterns", ()):
            matches = getattr(pattern, "matches", ())
            if not matches:
                continue

            identifier = getattr(pattern, "identifier", "")
            instances: List[YaraXStringMatchInstance] = []
            for m in matches:
                m_offset = getattr(m, "offset", 0)
                m_length = getattr(m, "length", 0)
                xor_key = getattr(m, "xor_key", None)

                if data is not None and data_len >= m_offset + m_length:
                    m_bytes = data[m_offset : m_offset + m_length]
                else:
                    m_bytes = b""

                instances.append(
                    YaraXStringMatchInstance(
                        offset=m_offset,
                        length=m_length,
                        matched_data=m_bytes,
                        xor_key=xor_key,
                        identifier=identifier,
                    )
                )

            if instances:
                strings_list.append(YaraXStringMatch(identifier, instances))

        self.strings: List[YaraXStringMatch] = strings_list

    def __repr__(self) -> str:
        return f"<YaraXMatch rule='{self.rule}' strings={len(self.strings)}>"


class YaraXRules:
    """Thread-safe wrapper around yara_x.Rules.

    yara_x.Scanner is PyO3 unsendable and cannot be moved or dropped across
    threads. yara_x.Rules is sendable. This class caches Rules and constructs
    Scanner per match() call on the calling thread.
    """

    __slots__ = ("_rules",)

    def __init__(self, rules_obj: Any):
        self._rules = rules_obj

    def match(
        self,
        filepath: Optional[str] = None,
        data: Optional[Union[bytes, bytearray, memoryview, str]] = None,
        externals: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        **kwargs: Any,
    ) -> List[YaraXMatch]:
        """Scans data or filepath with yara_x."""
        raw_bytes: bytes
        if filepath is not None and data is None:
            with open(filepath, "rb") as f:
                raw_bytes = f.read()
        elif data is not None:
            if isinstance(data, str):
                raw_bytes = data.encode("utf-8")
            elif isinstance(data, (bytearray, memoryview)):
                raw_bytes = bytes(data)
            elif isinstance(data, bytes):
                raw_bytes = data
            else:
                raw_bytes = bytes(data)
        else:
            raw_bytes = b""

        scanner = yara_x.Scanner(self._rules)
        if timeout is not None:
            scanner.set_timeout(int(timeout))
        if externals:
            for k, v in externals.items():
                scanner.set_global(k, v)

        scan_results = scanner.scan(raw_bytes)
        matching_rules = getattr(scan_results, "matching_rules", ())
        return [YaraXMatch(r, raw_bytes) for r in matching_rules]


def is_yara_x_available() -> bool:
    return HAVE_YARA_X


def is_yara_available() -> bool:
    return HAVE_YARA


def get_backend(backend: Optional[str] = None) -> str:
    """Resolves active backend ('yara_x' or 'yara')."""
    resolved = (backend or os.environ.get("CAPE_PARSERS_YARA_BACKEND", "auto")).lower()
    if resolved == "auto":
        if HAVE_YARA_X:
            return "yara_x"
        if HAVE_YARA:
            return "yara"
        raise YaraWrapperError("Neither yara_x nor yara-python is installed")
    if resolved in ("yara_x", "yarax"):
        if not HAVE_YARA_X:
            raise YaraWrapperError("yara_x requested but not installed")
        return "yara_x"
    if resolved in ("yara", "yara-python"):
        if not HAVE_YARA:
            raise YaraWrapperError("yara-python requested but not installed")
        return "yara"
    raise ValueError(f"Unknown YARA backend: {resolved}")


def compile(
    filepath: Optional[str] = None,
    source: Optional[str] = None,
    filepaths: Optional[Dict[str, str]] = None,
    sources: Optional[Dict[str, str]] = None,
    includes: bool = True,
    externals: Optional[Dict[str, Any]] = None,
    error_on_warning: bool = False,
    relaxed_re_syntax: bool = True,
    backend: Optional[str] = None,
) -> Any:
    """Compiles YARA rules using either yara_x or yara-python."""
    target_backend = get_backend(backend)

    if target_backend == "yara_x":
        compiler = yara_x.Compiler(relaxed_re_syntax=relaxed_re_syntax)
        if externals:
            for k, v in externals.items():
                compiler.define_global(k, v)
        if source is not None:
            compiler.add_source(source)
        if filepath is not None:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                compiler.add_source(f.read())
        if sources:
            for ns, src in sources.items():
                compiler.new_namespace(ns)
                compiler.add_source(src)
        if filepaths:
            for ns, fp in filepaths.items():
                compiler.new_namespace(ns)
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    compiler.add_source(f.read())
        return YaraXRules(compiler.build())

    # Fallback to yara-python
    compile_kwargs: Dict[str, Any] = {
        "includes": includes,
        "error_on_warning": error_on_warning,
    }
    if filepath is not None:
        compile_kwargs["filepath"] = filepath
    if source is not None:
        compile_kwargs["source"] = source
    if filepaths is not None:
        compile_kwargs["filepaths"] = filepaths
    if sources is not None:
        compile_kwargs["sources"] = sources
    if externals is not None:
        compile_kwargs["externals"] = externals

    return _yara.compile(**compile_kwargs)
