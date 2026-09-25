"""Check the bundled sing snapshot without an external checkout or network."""

import hashlib
import json
from pathlib import Path


def main():
    directory = Path(__file__).resolve().parent
    manifest = json.loads((directory / "sing-source.json").read_text(encoding="utf-8"))
    source = directory / "sing"
    digest = hashlib.sha256()
    count = size = 0
    for path in sorted(source.rglob("*"), key=lambda path: path.relative_to(source).as_posix()):
        if path.is_symlink():
            raise SystemExit(f"Unexpected symlink: {path}")
        if path.is_file():
            data = path.read_bytes()
            name = path.relative_to(source).as_posix()
            digest.update(name.encode() + b"\0" + hashlib.sha256(data).digest())
            count += 1
            size += len(data)
    if (count, size, digest.hexdigest()) != (manifest["files"], manifest["bytes"], manifest["sha256"]):
        raise SystemExit("Bundled sing differs from the reviewed snapshot; reconcile provenance before checkpointing")
    print(f"PASS: {count} files, {size} bytes, reviewed sing {manifest['reviewed_commit']}")


if __name__ == "__main__":
    main()
