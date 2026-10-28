import hashlib
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


COPY_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class ByteEdit:
    offset: int
    original: bytes
    replacement: bytes


def validate_edits(edits: tuple[ByteEdit, ...]):
    previous_end = 0
    for edit in edits:
        if edit.offset < previous_end:
            raise ValueError("Patch regions overlap or are not ordered")
        if len(edit.original) != len(edit.replacement):
            raise ValueError("Patch replacement length differs from original length")
        previous_end = edit.offset + len(edit.original)


def file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _publish(temporary: Path, destination: Path):
    # Both calls refuse an existing destination. rename also works on FAT and exFAT,
    # which have no hard links, but only Windows guarantees it never overwrites.
    if sys.platform == "win32":
        os.rename(temporary, destination)
    else:
        os.link(temporary, destination)


def write_verified_copy(source: Path, destination: Path, edits: tuple[ByteEdit, ...], expected_sha256: str):
    """Stream source to destination with edits, publishing only a file whose SHA-256 matches."""
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"Refusing to replace existing file {destination}")
    validate_edits(edits)

    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".fc6-", suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            with source.open("rb") as original:
                for edit in edits:
                    remaining = edit.offset - original.tell()
                    while remaining:
                        block = original.read(min(remaining, COPY_CHUNK_SIZE))
                        if not block:
                            raise ValueError("Original bytes end before patch region")
                        output.write(block)
                        remaining -= len(block)
                    if original.read(len(edit.original)) != edit.original:
                        raise ValueError(f"Original bytes differ at file offset {edit.offset:#x}")
                    output.write(edit.replacement)
                shutil.copyfileobj(original, output, COPY_CHUNK_SIZE)
            output.flush()
            os.fsync(output.fileno())
        actual = file_sha256(temporary)
        if actual != expected_sha256:
            raise ValueError(f"Output SHA-256 differs, expected {expected_sha256}, found {actual}")
        _publish(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
