"""Require the concurrent USER/Measurement regressions in one verbose OS log."""
import json
import re
import sys
from pathlib import Path


def required_cells():
    groups = {
        "native": ["vless", "vmess", "trojan", "2022-blake3-aes-128-gcm",
                   "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"],
        "additional": ["ss-aes128", "ss-aes256", "ss-chacha20", "ss-xchacha20", "socks", "http"],
        "vision": ["tls13", "reality"],
        "sender": ["tcp-mux", "persistent-xudp"],
        "transport": ["websocket", "grpc", "packet-up", "stream-up", "stream-one"],
    }
    profiles = [f"TestB7CombinedProfiles/{group}/{profile}"
                for group, names in groups.items() for profile in names]
    profiles += [f"TestB7CombinedProfiles/{name}" for name in ("freedom", "hysteria", "wireguard")]
    assert len(profiles) == 24
    profiles += ["TestB7CombinedProfiles/grpc-multi"]
    required = ["TestB7CombinedProfiles", "TestB7ObservationModes"]
    for profile in profiles:
        node = profile + "/working-node"
        required += [profile, node, node + "/handler-changes"]
        for route in ("2-exact", "2-second", "1-"):
            for wave in range(3):
                for mode in ("success", "failure", "cancel"):
                    required.append(f"{node}/wave{wave}/{route}/{mode}")
            if not profile.endswith("/http") or route == "1-":
                for mode in ("echo", "malformed", "cancel"):
                    required.append(f"{node}/UDP/{route}/{mode}")
    required += [f"TestB7ObservationModes/{mode}" for mode in (
        "no-store", "inspection-off", "enabled-sufficient", "enabled-constrained")]
    assert len(required) == len(set(required))
    return required


def check_log(text, repetitions=1):
    if repetitions < 1:
        raise ValueError("positive repetition count required")
    events = {}
    passes = {}
    for action, name in re.findall(r"--- (PASS|SKIP|FAIL): (\S+) \(", text.replace("\x00", "")):
        events.setdefault(name, set()).add(action)
        if action == "PASS":
            passes[name] = passes.get(name, 0) + 1
    required = required_cells()
    missing = [name for name in required if name not in events]
    incomplete = {name: passes.get(name, 0) for name in required
                  if passes.get(name, 0) < repetitions}
    bad = {name: sorted(events[name]) for name in required
           if name in events and events[name] != {"PASS"}}
    # A failure in any B7 descendant is a blocker, even outside required cells.
    unexpected = {name: sorted(actions) for name, actions in events.items()
                  if name.startswith(("TestB7CombinedProfiles/", "TestB7ObservationModes/"))
                  and actions != {"PASS"}}
    return {"profiles": 24, "additional_multimode": 1, "required_cells": len(required),
            "repetitions": repetitions,
            "passed": sum(events.get(name) == {"PASS"} and passes.get(name, 0) >= repetitions for name in required),
            "missing": missing, "bad": bad, "incomplete_repetitions": incomplete,
            "nonpassing_descendants": unexpected}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--repetitions", type=int, default=1)
    args = parser.parse_args()
    result = check_log(args.log.read_bytes().decode("utf-8", "replace"), args.repetitions)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if not result["missing"] and not result["bad"] and not result["incomplete_repetitions"] and
                     not result["nonpassing_descendants"] else 1)
