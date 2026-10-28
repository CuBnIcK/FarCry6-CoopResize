"""Every known FC_m64d3d12.dll variant: how to build it, its hashes, and its loaded-code probes."""

import hashlib
import json
import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from fc6 import capacity, peer_table, session_request, storm_peers
from fc6.build import BUILDS, STEAM, TARGET_DLL, TEXT1, UBISOFT, Build, identify_build
from fc6.edits import COPY_CHUNK_SIZE, ByteEdit, file_sha256, validate_edits, write_verified_copy


@dataclass(frozen=True)
class Component:
    name: str
    edits: Callable[[Path, Build], tuple[ByteEdit, ...]]
    probes: Callable[[Build], dict[int, bytes]]
    # Reference .text1 RVA, every build keeps the same layout inside the section
    text1_end: int = TEXT1.rva + TEXT1.virtual_size


@dataclass(frozen=True)
class Variant:
    name: str
    sha256: str  # Steam result
    summary: str
    components: tuple[Component, ...] = ()
    # Build name -> result for the other builds this variant is published for
    other_hashes: Mapping[str, str] = field(default_factory=dict)

    def hash_for(self, build: Build) -> str | None:
        return self.sha256 if build is STEAM else self.other_hashes.get(build.name)

    def text1_virtual_size(self) -> int:
        return max(component.text1_end for component in self.components) - TEXT1.rva

    def edits(self, source: Path, build: Build = STEAM) -> tuple[ByteEdit, ...]:
        if not self.components:
            return ()
        edits = [edit for component in self.components for edit in component.edits(source, build)]
        edits.append(ByteEdit(build.text1.virtual_size_field, struct.pack("<I", build.text1.virtual_size),
                              struct.pack("<I", self.text1_virtual_size())))
        edits.sort(key=lambda edit: edit.offset)
        validate_edits(tuple(edits))
        return tuple(edits)

    def probes(self, build: Build = STEAM) -> dict[int, bytes]:
        probes = {}
        for component in self.components:
            for rva, expected in component.probes(build).items():
                if probes.get(rva, expected) != expected:
                    raise ValueError(f"Components disagree about RVA {rva:#x}")
                probes[rva] = expected
        if self.components:
            probes[build.text1.virtual_size_field] = struct.pack("<I", self.text1_virtual_size())
        return probes


CAMPAIGN = Component("campaign capacity", lambda _, build: capacity.build_edits("campaign", build),
                     lambda build: capacity.patched_code_probes("campaign", build), capacity.text1_end("campaign"))
COOP_DLC = Component("co-op DLC capacity", lambda _, build: capacity.build_edits("coop-dlc", build),
                     lambda build: capacity.patched_code_probes("coop-dlc", build), capacity.text1_end("coop-dlc"))
REQUEST_NUMBER = Component("numeric sessions request",
                           lambda source, build: session_request.build_edits(source, False, build),
                           lambda build: session_request.patched_code_probes(False, build),
                           session_request.text1_end(False))
REQUEST_STRING = Component("string sessions request",
                           lambda source, build: session_request.build_edits(source, True, build),
                           lambda build: session_request.patched_code_probes(True, build),
                           session_request.text1_end(True))
STORM_PEERS = Component("Storm peer limit", lambda _, build: storm_peers.build_edits(build),
                        storm_peers.patched_code_probes)
PEER_TABLE = Component("P2P peer table", lambda _, build: peer_table.build_edits(build),
                       peer_table.patched_code_probes)
PEER_OWNER = Component("P2P object owner peer", lambda _, build: peer_table.build_owner_edits(build),
                       peer_table.owner_code_probes)

ORIGINAL = Variant("original", STEAM.sha256, "Unmodified game DLL",
                   other_hashes={UBISOFT.name: UBISOFT.sha256})
VARIANTS = {variant.name: variant for variant in (
    ORIGINAL,
    Variant("campaign", "126ab98f1c47380cd4f2f2c6ca32f0c8785a12055ab5d1fd58aec474b977fe20",
            "Local campaign capacity 4, superseded", (CAMPAIGN,)),
    Variant("coop-dlc", "58a951369f8079c1da28bce84b03d5744917c5541f5232ec98c8bb7a2e41879c",
            "Local capacity 4 for campaign, Operations and Inside the Mind, superseded", (COOP_DLC,)),
    Variant("request-number", "566975b0126df772b6513b24758eaef8e92928f305c427d62da901c1c86be67b",
            "coop-dlc plus numeric overrides.maxTeamSize, host creation failed (Snowshoe)",
            (COOP_DLC, REQUEST_NUMBER)),
    Variant("request-string", "1d7557fd56adecef2c15d907a730f81aced17e41b27783c6617d4a4d41045e5f",
            "coop-dlc plus string overrides.maxTeamSize, third player gets Bookworm-1E2AEC01",
            (COOP_DLC, REQUEST_STRING)),
    Variant("storm-peers", "f8ee1c8fd38226fe6d51c9b6dbecd0ada226b7268477788be3e9267efb0cc19b",
            "request-string plus Storm maxPeers 4, install on every player's PC",
            (COOP_DLC, REQUEST_STRING, STORM_PEERS)),
    Variant("peer-table", "15d4b5784a484b449e1ce24e6205515459cee9c8a0bae0c8da4579c1edacce73",
            "storm-peers plus the P2P peer table for ids 2 and 3, install on every player's PC",
            (COOP_DLC, REQUEST_STRING, STORM_PEERS, PEER_TABLE)),
    Variant("peer-owner", "01e6535b6613b50cc2147ec94b1bb414b4e1ab04797dae2119d9bb51f9b82a0c",
            "peer-table plus object owner checks for ids 2 and 3, three players confirmed in game",
            (COOP_DLC, REQUEST_STRING, STORM_PEERS, PEER_TABLE, PEER_OWNER),
            {UBISOFT.name: "75bfd8fc3f17f5246e478edbacc4e9a1fbf7f0c8ca73320fa7ff8f1ab840c0b6"}),
)}
RECOMMENDED = "peer-owner"


def get_variant(name: str) -> Variant:
    try:
        return VARIANTS[name]
    except KeyError as error:
        raise ValueError(f"Unknown variant {name}, choose one of {', '.join(VARIANTS)}") from error


def identify(sha256: str) -> Variant | None:
    """Steam variants only, the read-only observer knows only the Steam layout."""
    return next((variant for variant in VARIANTS.values() if variant.sha256 == sha256), None)


def identify_any(sha256: str) -> tuple[Variant, Build] | None:
    for build in BUILDS.values():
        for variant in VARIANTS.values():
            if variant.hash_for(build) == sha256:
                return variant, build
    return None


def patched_sha256(source: Path, edits: tuple[ByteEdit, ...]) -> str:
    """SHA-256 of source with edits applied, without writing a file."""
    validate_edits(edits)
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        for edit in edits:
            remaining = edit.offset - stream.tell()
            while remaining:
                block = stream.read(min(remaining, COPY_CHUNK_SIZE))
                if not block:
                    raise ValueError("Original bytes end before patch region")
                digest.update(block)
                remaining -= len(block)
            if stream.read(len(edit.original)) != edit.original:
                raise ValueError(f"Original bytes differ at file offset {edit.offset:#x}")
            digest.update(edit.replacement)
        while block := stream.read(COPY_CHUNK_SIZE):
            digest.update(block)
    return digest.hexdigest()


def create_package(source: Path, output_directory: Path, variant_name: str = RECOMMENDED) -> dict:
    """Write a verified pristine backup, the patched DLL and patch-info.json. Installs nothing."""
    variant = get_variant(variant_name)
    if variant is ORIGINAL:
        raise ValueError("Choose a patched variant, the original needs no package")
    source = source.resolve(strict=True)
    actual = file_sha256(source)
    build = identify_build(actual)
    if build is None:
        known = identify_any(actual)
        if known:
            raise ValueError(f"Source is already the {known[1].name} {known[0].name} variant, "
                             f"use the unmodified DLL or its .bak backup")
        raise ValueError(f"Source SHA-256 is unsupported, found {actual}")
    expected = variant.hash_for(build)
    if expected is None:
        available = [item.name for item in VARIANTS.values() if item is not ORIGINAL and item.hash_for(build)]
        raise ValueError(f"Variant {variant.name} is not available for the {build.name} build, "
                         f"choose {', '.join(available)}")
    edits = variant.edits(source, build)
    output_directory = output_directory.resolve()
    patched = output_directory / TARGET_DLL
    backup = output_directory / (TARGET_DLL + ".bak")
    info_path = output_directory / "patch-info.json"
    for destination in (backup, patched, info_path):
        if destination == source or destination.exists() or destination.is_symlink():
            raise FileExistsError(f"Refusing to replace existing file {destination}")
    output_directory.mkdir(parents=True, exist_ok=True)
    write_verified_copy(source, backup, (), build.sha256)
    write_verified_copy(backup, patched, edits, expected)
    info = {
        "status": "EXPERIMENTAL_NOT_INSTALLED",
        "build": build.name,
        "build_description": build.description,
        "variant": variant.name,
        "summary": variant.summary,
        "components": [component.name for component in variant.components],
        "original_sha256": build.sha256,
        "patched_sha256": expected,
        "modified_regions": len(edits),
        "modified_bytes": sum(a != b for edit in edits for a, b in zip(edit.original, edit.replacement)),
        "original_backup": str(backup),
        "patched_dll": str(patched),
        "install": f"Close the game, keep the backup, copy {TARGET_DLL} over the game's bin\\{TARGET_DLL}",
        "restore": f"Close the game, copy {TARGET_DLL}.bak over the game's bin\\{TARGET_DLL}",
    }
    with info_path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(info, indent=2) + "\n")
    return info
