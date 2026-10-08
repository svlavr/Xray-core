"""Check required Measurement profile cells in one OS's verbose Go test log."""
import json
import re
import sys
from pathlib import Path

PROFILES = [
    "TestTransportProfileMeasurements/" + p
    for p in ("websocket", "grpc", "packet-up", "stream-up", "stream-one")
] + [
    "TestSenderMUXProfileMeasurements/" + p for p in ("tcp-mux", "persistent-xudp")
] + [
    "TestVisionProfileMeasurements/" + p for p in ("tls13", "reality")
] + [
    "TestNativeProtocolMeasurements/" + p for p in (
        "vless", "vmess", "trojan", "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305")
] + [
    "TestAdditionalProtocolMeasurements/" + p for p in (
        "ss-aes128", "ss-aes256", "ss-chacha20", "ss-xchacha20", "socks", "http")
] + [
    "TestHysteriaMeasurementSeriesAndUDPCancellation",
    "TestFreedomProtocolMeasurements", "TestWireGuardProtocolMeasurements",
]


def required_cells():
    required = []
    for profile in PROFILES:
        required += [profile, profile + "/working-node", profile + "/working-node/handler-changes"]
        for route in ("2-exact", "2-second", "1-"):
            for wave in range(3):
                for mode in ("success", "failure", "cancel"):
                    required.append(f"{profile}/working-node/wave{wave}/{route}/{mode}")
            if not profile.endswith("/http") or route == "1-":
                for mode in ("echo", "malformed", "cancel"):
                    required.append(f"{profile}/working-node/UDP/{route}/{mode}")
        if not profile.endswith("/http"):
            family = "ipv6-inner" if profile == "TestWireGuardProtocolMeasurements" else "ipv6"
            for tag in ("exact", "second"):
                for offset in ("-1", "0", "1"):
                    required.append(f"{profile}/{family}/packet-boundary/{tag}/{offset}")
    assert len(PROFILES) == 24 and len(required) == len(set(required)) == 1068
    return required


def check_log(text):
    events = {}
    for action, name in re.findall(r"--- (PASS|SKIP|FAIL): (\S+) \(", text.replace("\x00", "")):
        events.setdefault(name, set()).add(action)
    required = required_cells()
    missing = [name for name in required if name not in events]
    bad = {name: sorted(events[name]) for name in required if name in events and events[name] != {"PASS"}}
    skipped = sorted(name for name, actions in events.items() if "SKIP" in actions and any(
        name == profile or name.startswith(profile + "/") for profile in PROFILES))
    return {"profiles": 24, "required_cells": 1068,
            "passed": sum(events.get(name) == {"PASS"} for name in required),
            "missing": missing, "bad": bad, "profile_skips": skipped}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_measurement_coverage.py <verbose-test-log>")
    result = check_log(Path(sys.argv[1]).read_bytes().decode("utf-8", "replace"))
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["passed"] == 1068 and not result["missing"] and
                     not result["bad"] and not result["profile_skips"] else 1)
