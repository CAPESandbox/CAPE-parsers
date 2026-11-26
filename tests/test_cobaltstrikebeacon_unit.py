import struct

from cape_parsers.CAPE.community import CobaltStrikeBeacon


def _build_setting(pos: int, datatype: int, payload: bytes) -> bytes:
    return struct.pack(">HHH", pos, datatype, len(payload)) + payload


def test_cobaltstrike_execute_type_length_prefixed_strings():
    mod = b"ntdll.dll\x00"
    func = b"RtlExitUserThread\x00"
    exec_blob = (
        b"\x01"  # CreateThread
        + b"\x06\x00\x00"  # EXECUTE_TYPE 0x6 + unknown short
        + struct.pack(">I", len(mod))
        + mod
        + struct.pack(">I", len(func))
        + func
        + b"\x03"  # CreateRemoteThread
        + b"\x00"  # terminator
    ).ljust(128, b"\x00")

    setting = CobaltStrikeBeacon.BeaconSettings(4).settings["ProcInject_Execute"]
    full_cfg = _build_setting(51, CobaltStrikeBeacon.confConsts.TYPE_STR, exec_blob)
    result = setting.pretty_repr(full_cfg)
    assert result == ["CreateThread", "ntdll.dll:RtlExitUserThread", "CreateRemoteThread"]


def test_cobaltstrike_execute_type_truncated_does_not_raise():
    exec_blob = (b"\x01\x06\x00\x00" + struct.pack(">I", 200) + b"short").ljust(128, b"\x00")
    setting = CobaltStrikeBeacon.BeaconSettings(4).settings["ProcInject_Execute"]
    full_cfg = _build_setting(51, CobaltStrikeBeacon.confConsts.TYPE_STR, exec_blob)
    result = setting.pretty_repr(full_cfg)
    assert result == ["CreateThread"]
