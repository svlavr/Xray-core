#!/usr/bin/env python3
"""Run the same bounded UDP controls in isolated official and fork source copies."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys
import tarfile
import time


OFFICIAL = "60e2a0c502d3f5f191d71b4343efe09c32338399"
SHA = re.compile(r"^[0-9a-f]{40}$")
MODES = ("official", "off", "on")
PROBE_PATH = PurePosixPath(".control/udp/udp_controls_test.go")


def positive(value: str, maximum: int) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an integer") from exc
    if not 1 <= number <= maximum:
        raise argparse.ArgumentTypeError(f"expected 1..{maximum}")
    return number


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--official", default=OFFICIAL)
    parser.add_argument("--fork", required=True)
    parser.add_argument("--mode", action="append", choices=MODES, dest="modes")
    parser.add_argument("--repeat", type=lambda x: positive(x, 5), default=2)
    parser.add_argument("--iterations", type=lambda x: positive(x, 64), default=20)
    parser.add_argument("--ports", type=lambda x: positive(x, 512), default=256)
    parser.add_argument("--go", default="go")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    args.modes = args.modes or list(MODES)
    if len(set(args.modes)) != len(args.modes) or tuple(args.modes) != tuple(mode for mode in MODES if mode in args.modes):
        parser.error("modes must be a unique official/off/on subsequence")
    for label in ("official", "fork"):
        if not SHA.fullmatch(getattr(args, label)):
            parser.error(f"--{label} must be a full lowercase 40-digit commit SHA")
    return args


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.STDOUT)


def validate_paths(repo: Path, output: Path) -> tuple[Path, Path]:
    repo = repo.resolve(strict=True)
    if Path(git(repo, "rev-parse", "--show-toplevel").decode().strip()).resolve() != repo:
        raise ValueError("--repo must name the Git root")
    output = output.resolve()
    if output.exists() or output == repo or output.is_relative_to(repo) or repo.is_relative_to(output):
        raise ValueError("--output must be a new path outside the repository")
    return repo, output


def archive(repo: Path, revision: str, destination: Path) -> None:
    kind = git(repo, "cat-file", "-t", revision).decode().strip()
    if kind != "commit":
        raise ValueError(f"{revision} is not a local commit")
    destination.mkdir(parents=True)
    process = subprocess.Popen(
        ["git", "-C", str(repo), "archive", "--format=tar", revision],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    with tarfile.open(fileobj=process.stdout, mode="r|") as stream:
        for member in stream:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or ".." in name.parts or "\\" in member.name or
                    not name.parts or name.parts[0] in ("", ".")):
                process.kill()
                raise ValueError(f"unsafe archive member {member.name!r}")
            target = destination.joinpath(*name.parts)
            if not target.resolve().is_relative_to(destination.resolve()):
                process.kill()
                raise ValueError(f"archive member escaped destination {member.name!r}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = stream.extractfile(member)
                if source is None:
                    process.kill()
                    raise ValueError(f"cannot read archive member {member.name!r}")
                with source, target.open("xb") as written:
                    while chunk := source.read(1024 * 1024):
                        written.write(chunk)
                if member.mode & 0o111:
                    target.chmod(0o755)
            else:
                process.kill()
                raise ValueError(f"archive contains unsupported link/device {member.name!r}")
    stderr = process.stderr.read().decode(errors="replace") if process.stderr else ""
    if process.wait() != 0:
        raise RuntimeError(f"git archive failed: {stderr}")


def hashes(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"source copy contains symlink {path}")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = sha256(path.read_bytes())
    return result


def tree_digest(files: dict[str, str]) -> str:
    return sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())


def go_environment(go: str) -> dict[str, object]:
    result = subprocess.run([go, "env", "-json", "GOOS", "GOARCH", "GOVERSION"], capture_output=True, text=True, check=True)
    version = subprocess.run([go, "version"], capture_output=True, text=True, check=True)
    return {"env": json.loads(result.stdout), "version": version.stdout.strip()}


def run_case(go: str, root: Path, log_dir: Path, label: str, args: list[str], environment: dict[str, str], race: bool) -> dict[str, object]:
    command = [go, "test", "-mod=readonly", "-json", "-v", "-count=1", "-timeout=120s"]
    if race:
        command.append("-race")
    command.extend(args)
    log_path = log_dir / f"{label}.jsonl"
    print("CONTROL_CASE", label, "command=", json.dumps(command), flush=True)
    started = time.monotonic()
    timed_out = False
    process = subprocess.Popen(command, cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", start_new_session=True)
    try:
        output, _ = process.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        timed_out = True
        # Kill the entire isolated group: go may have spawned a test binary or
        # compiler that still owns sockets or the captured stdout pipe.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        output, _ = process.communicate()
    code = process.returncode
    with log_path.open("w", encoding="utf-8") as log:
        log.write(output)
    # Go event lines remain in job stdout for the read-only CI interface.
    for line in output.splitlines():
        print(f"CONTROL_EVENT {label} {line}", flush=True)
    outcomes = []
    failing = []
    output_lines = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            if len(failing) < 20:
                failing.append(line[:500])
            continue
        if event.get("Action") in ("pass", "fail", "skip"):
            outcomes.append({key: event[key] for key in ("Package", "Test", "Action", "Elapsed") if key in event})
        if event.get("Action") == "output" and event.get("Output"):
            output_lines.append(str(event["Output"]).rstrip()[:500])
        if event.get("Action") == "fail" and len(failing) < 20:
            failing.append(json.dumps(event, ensure_ascii=False)[:500])
    diagnostic_lines = []
    if code != 0 or timed_out:
        markers = ("session", "conversation", "conv=", "connection", "invalid", "payload", "packet", "fail", "error")
        interesting = [line for line in output_lines[-500:] if any(marker in line.lower() for marker in markers)]
        for line in [*interesting[-60:], *output_lines[-40:]]:
            if line not in diagnostic_lines:
                diagnostic_lines.append(line)
        for line in diagnostic_lines:
            print(f"CONTROL_DIAGNOSTIC {label} {line}", flush=True)
    print(f"CONTROL_RESULT {label} exit={code} timeout={timed_out} seconds={time.monotonic()-started:.3f} failures={json.dumps(failing)}", flush=True)
    return {
        "label": label, "race": race, "command": command,
        "env": {key: environment[key] for key in ("XRAY_CONTROL_MODE", "XRAY_CONTROL_ITERATIONS", "XRAY_CONTROL_PORTS", "GOTOOLCHAIN")},
        "exit": code, "timeout": timed_out, "seconds": round(time.monotonic() - started, 3),
        "log": str(log_path), "outcomes": outcomes, "failure_events": failing,
        "failure_context": diagnostic_lines,
    }


def write_manifest(path: Path, manifest: dict[str, object]) -> None:
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    if os.name != "posix" and not args.prepare_only:
        raise ValueError("test execution requires POSIX process-group cleanup; Windows supports --prepare-only")
    repo, output = validate_paths(args.repo, args.output)
    template_path = repo / ".github" / "diagnostics" / "udp_controls_test.go.txt"
    probe = template_path.read_bytes()
    environment = go_environment(args.go)
    output.mkdir(parents=True)
    manifest: dict[str, object] = {
        "schema": 1, "repo": str(repo), "official": args.official, "fork": args.fork,
        "modes": args.modes, "repeat": args.repeat, "iterations": args.iterations,
        "ports": args.ports, "probe_path": PROBE_PATH.as_posix(), "probe_sha256": sha256(probe),
        "go": environment, "prepare_only": args.prepare_only, "copies": [],
    }
    manifest_path = output / "manifest.json"
    failed = False
    for mode in args.modes:
        revision = args.official if mode == "official" else args.fork
        for repetition in range(1, args.repeat + 1):
            label = f"{mode}-{repetition}"
            root = output / label / "source"
            logs = output / label / "logs"
            copy: dict[str, object] = {"mode": mode, "repeat": repetition, "revision": revision, "root": str(root), "cases": []}
            manifest["copies"].append(copy)
            try:
                archive(repo, revision, root)
                if (root / PROBE_PATH.as_posix()).exists():
                    raise ValueError("archive already contains probe destination")
                destination = root / PROBE_PATH.as_posix()
                destination.parent.mkdir(parents=True)
                destination.write_bytes(probe)
                before = hashes(root)
                copy["before_sha256"] = tree_digest(before)
                copy["before_files"] = len(before)
                copy["probe_sha256"] = before[PROBE_PATH.as_posix()]
                if not args.prepare_only:
                    logs.mkdir()
                    env = os.environ.copy()
                    env.update({
                        "XRAY_CONTROL_MODE": mode,
                        "XRAY_CONTROL_ITERATIONS": str(args.iterations),
                        "XRAY_CONTROL_PORTS": str(args.ports),
                        "GOTOOLCHAIN": "local",
                    })
                    cohorts = (
                        ("probe", ["./.control/udp", "-run", "^TestControl"]),
                        ("kcp", ["./transport/internet/kcp", "-run", "^TestDialAndListen$"]),
                        ("coscheduled", ["-p=2", "./transport/internet/kcp", "./.control/udp", "-run", "^(TestDialAndListen|TestControlSOCKSUDP|TestControlUDPPortAllocation)$"]),
                    )
                    for suite, race in (("ordinary", False), ("race", True)):
                        for cohort, command in cohorts:
                            case = run_case(args.go, root, logs, f"{suite}-{cohort}", command, env, race)
                            copy["cases"].append(case)
                            if case["exit"] != 0 or case["timeout"]:
                                failed = True
                after = hashes(root)
                copy["after_sha256"] = tree_digest(after)
                copy["after_files"] = len(after)
                changed = sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))
                copy["changed_paths"] = changed
                if changed:
                    failed = True
                    print(f"CONTROL_SOURCE_CHANGED {label} {json.dumps(changed)}", flush=True)
                else:
                    print(f"CONTROL_SOURCE_OK {label} sha256={copy['after_sha256']} files={len(after)}", flush=True)
            except Exception as exc:
                failed = True
                copy["error"] = f"{type(exc).__name__}: {exc}"
                print(f"CONTROL_ERROR {label} {copy['error']}", flush=True)
            write_manifest(manifest_path, manifest)
    print(f"CONTROL_MANIFEST {manifest_path} failed={failed}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
