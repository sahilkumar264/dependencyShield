#!/usr/bin/env python3
"""Extract a GitHub source tarball without writing links or special files."""
import os
import pathlib
import sys
import tarfile

MAX_ENTRIES = 50000
MAX_EXPANDED_BYTES = 500 * 1024 * 1024

archive = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2]).resolve()
destination.mkdir(parents=True, exist_ok=True)
total = 0
entries = 0
top_level = None

with tarfile.open(archive, mode="r:gz") as source:
    for member in source:
        entries += 1
        if entries > MAX_ENTRIES:
            raise RuntimeError("repository archive contains too many entries")
        raw = member.name.replace("\\", "/")
        path = pathlib.PurePosixPath(raw)
        if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
            raise RuntimeError("repository archive contains an unsafe path")
        if top_level is None:
            top_level = path.parts[0]
        if path.parts[0] != top_level:
            raise RuntimeError("repository archive has multiple root directories")
        relative = pathlib.PurePosixPath(*path.parts[1:])
        if not relative.parts:
            continue
        if not (member.isdir() or member.isfile()):
            continue
        target = (destination / pathlib.Path(*relative.parts)).resolve()
        if destination not in target.parents and target != destination:
            raise RuntimeError("repository archive path escapes extraction directory")
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        total += member.size
        if member.size < 0 or total > MAX_EXPANDED_BYTES:
            raise RuntimeError("repository archive exceeds the expanded size limit")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise RuntimeError("repository archive contains duplicate paths")
        extracted = source.extractfile(member)
        if extracted is None:
            continue
        with extracted, target.open("xb") as output:
            remaining = member.size
            while remaining:
                chunk = extracted.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise RuntimeError("truncated repository archive entry")
                output.write(chunk)
                remaining -= len(chunk)
