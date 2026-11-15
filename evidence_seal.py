#!/usr/bin/env python3
"""Create and verify SHA-256 manifests for evidence directories."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


MANIFEST_FORMAT = "evidence-seal-sha256-v1"
CHUNK_SIZE = 1024 * 1024


def fingerprint(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns,
    )


def hash_file(dir_fd, name, relative_path, observed):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    digest = hashlib.sha256()
    bytes_read = 0
    fd = os.open(name, flags, dir_fd=dir_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or fingerprint(before) != fingerprint(observed):
            raise ValueError(f"file changed before hashing: {relative_path!r}")
        while chunk := stream.read(CHUNK_SIZE):
            digest.update(chunk)
            bytes_read += len(chunk)
        after = os.fstat(stream.fileno())
        current = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if (
            bytes_read != before.st_size
            or fingerprint(before) != fingerprint(after)
            or fingerprint(after) != fingerprint(current)
        ):
            raise ValueError(f"file changed during hashing: {relative_path!r}")
    return {"path": relative_path, "size": bytes_read, "sha256": digest.hexdigest()}


def raise_walk_error(error):
    raise error


def scan(root):
    entries = {}
    for directory, subdirs, names, dir_fd in os.fwalk(
        root, onerror=raise_walk_error, follow_symlinks=False
    ):
        for name in subdirs:
            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                path = (Path(directory) / name).relative_to(root).as_posix()
                raise ValueError(f"expected a real directory: {path!r}")
        for name in names:
            path = (Path(directory) / name).relative_to(root).as_posix()
            observed = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if not stat.S_ISREG(observed.st_mode):
                raise ValueError(f"expected a regular file: {path!r}")
            entries[path] = hash_file(dir_fd, name, path, observed)
    return entries


def write_manifest(path, entries):
    fd, temp_name = tempfile.mkstemp(prefix=".evidence-seal-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(
                {"format": MANIFEST_FORMAT, "files": [entries[key] for key in sorted(entries)]},
                handle,
                indent=2,
                ensure_ascii=True,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        # Publish the completed file without overwriting an existing manifest.
        os.link(temp_name, path)
    finally:
        os.unlink(temp_name)


def read_manifest(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, encoding="utf-8") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("the manifest must be a regular file")
        manifest = json.load(handle)
    if (
        not isinstance(manifest, dict)
        or manifest.get("format") != MANIFEST_FORMAT
        or not isinstance(manifest.get("files"), list)
    ):
        raise ValueError("expected an Evidence Seal v1 manifest")
    entries = {}
    for position, entry in enumerate(manifest["files"], 1):
        if not isinstance(entry, dict) or entry.keys() != {"path", "size", "sha256"}:
            raise ValueError(f"invalid fields in manifest entry {position}")
        name, size, digest = entry["path"], entry["size"], entry["sha256"]
        if (
            not isinstance(name, str)
            or any(part in {"", ".", ".."} for part in name.split("/"))
            or "\x00" in name
            or type(size) is not int
            or size < 0
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ValueError(f"invalid value in manifest entry {position}")
        if name in entries:
            raise ValueError(f"duplicate manifest path: {name!r}")
        entries[name] = entry
    return entries


def verify(expected, actual):
    added = actual.keys() - expected.keys()
    missing = expected.keys() - actual.keys()
    changed = {
        path for path in expected.keys() & actual.keys() if expected[path] != actual[path]
    }
    for label, paths in (("ADDED", added), ("MISSING", missing), ("CHANGED", changed)):
        for path in sorted(paths):
            print(label, json.dumps(path))
    if added or missing or changed:
        print(f"Mismatch: {len(added)} added, {len(missing)} missing, {len(changed)} changed.")
        return 1
    print(f"Verified {len(actual)} file(s).")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("snapshot", "write a new manifest"),
        ("verify", "compare files against a manifest"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("directory", type=Path, help="evidence directory")
        command.add_argument("manifest", type=Path, help="manifest outside the evidence directory")
    args = parser.parse_args(argv)

    try:
        if os.name != "posix" or not hasattr(os, "fwalk"):
            raise ValueError("Evidence Seal requires macOS or Linux")
        if args.directory.is_symlink():
            raise ValueError("the evidence directory must not be a symbolic link")
        root = args.directory.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("the evidence path must be a directory")
        manifest = args.manifest.parent.resolve(strict=True) / args.manifest.name
        if manifest.is_relative_to(root) or manifest.resolve().is_relative_to(root):
            raise ValueError("the manifest must be outside the evidence directory")
        if args.command == "verify":
            expected = read_manifest(manifest)
            return verify(expected, scan(root))
        if os.path.lexists(manifest):
            raise FileExistsError(f"manifest already exists: {str(manifest)!r}")
        entries = scan(root)
        write_manifest(manifest, entries)
        print(f"Recorded {len(entries)} file(s) in {str(manifest)!r}.")
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
