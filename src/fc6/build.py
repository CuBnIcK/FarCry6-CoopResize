"""Identity and layout of every supported FC_m64d3d12.dll.

Steam app 2369390, depot 2369391, manifest 5783041166523199015 is the reference build.
Every RVA constant in this package belongs to it. Other builds carry a relocation table
from those reference RVAs to their own, found by matching whole functions instruction by
instruction. Check the SHA-256 before using any address.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field


TARGET_EXE = "FarCry6.exe"
TARGET_DLL = "FC_m64d3d12.dll"


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    virtual_size: int
    file_offset: int
    raw_size: int
    header_offset: int

    @property
    def virtual_size_field(self) -> int:
        """File offset of IMAGE_SECTION_HEADER.Misc.VirtualSize, also its RVA in the mapped header."""
        return self.header_offset + 8

    def contains(self, rva: int, size: int = 1) -> bool:
        return self.rva <= rva and rva + size <= self.rva + self.raw_size


@dataclass(frozen=True)
class Build:
    name: str
    description: str
    sha256: str
    file_size: int
    image_size: int
    # Only the sections that patches touch, copied from the original section table
    sections: tuple[Section, ...]
    text1: Section
    exception_section: Section
    # IMAGE_DIRECTORY_ENTRY_EXCEPTION
    exception_directory_size_field: int
    exception_table_rva: int
    exception_table_size: int
    # RUNTIME_FUNCTION index where the request stub is inserted
    exception_insert_index: int
    # Reference (Steam) RVA -> RVA in this build. .text1 addresses move with the section.
    relocations: Mapping[int, int] = field(default_factory=dict)

    def rva(self, reference_rva: int) -> int:
        if self is STEAM:
            return reference_rva
        if STEAM.text1.contains(reference_rva):
            return reference_rva - STEAM.text1.rva + self.text1.rva
        try:
            return self.relocations[reference_rva]
        except KeyError as error:
            raise ValueError(f"RVA {reference_rva:#x} has no known address in the {self.name} build") from error

    def file_offset(self, rva: int, size: int = 1) -> int:
        for section in self.sections:
            if section.contains(rva, size):
                return section.file_offset + rva - section.rva
        raise ValueError(f"RVA {rva:#x} is outside the known raw section data")


_STEAM_TEXT1 = Section(".text1", 0x1E9F8000, 0x9, 0x1DC9EA00, 0x200, 0x328)
_STEAM_EXCEPTIONS = Section(".???1", 0x1F111000, 0x786558, 0x1E3B3400, 0x786600, 0x440)
STEAM = Build(
    name="steam",
    description="Steam, manifest 5783041166523199015, PE timestamp 0x644bbd74",
    sha256="e82c7320c8554d0ac975c256db1c79ec046c0448e5b81bf50e3012b3642061aa",
    file_size=521313320,
    image_size=0x1FE87000,
    sections=(
        Section(".xtls", 0x1000, 0x576E000, 0x600, 0x576E000, 0x1E8),
        Section(".tls", 0x77A7000, 0x17205D15, 0x6A4DE00, 0x17205E00, 0x2B0),
        _STEAM_TEXT1,
        _STEAM_EXCEPTIONS,
    ),
    text1=_STEAM_TEXT1,
    exception_section=_STEAM_EXCEPTIONS,
    exception_directory_size_field=0x184,
    exception_table_rva=0x1F31ACD0,
    exception_table_size=0x57C888,
    exception_insert_index=478417,
)

# Ubisoft Connect build, a later compile of the same code with renamed sections. Every function
# that the patches touch or call has the same instructions, only the addresses moved.
_UBISOFT_TEXT1 = Section(".xtext", 0x1E1FF000, 0x9, 0x1D4E1400, 0x200, 0x348)
_UBISOFT_EXCEPTIONS = Section(".:Dg", 0x1EB42000, 0xA54A04, 0x1DE20C00, 0xA54C00, 0x460)
UBISOFT = Build(
    name="ubisoft",
    description="Ubisoft Connect, PE timestamp 0x6824d119",
    sha256="efe842af2a4b1cd78c56ca6d2d9b98669099f865ccbb1e3878578a071bf2a7ae",
    file_size=518275080,
    image_size=0x1FB64000,
    sections=(
        Section(".debug$P", 0x1000, 0x575BC00, 0x600, 0x575BC00, 0x1E0),
        Section(".xdata", 0x76D4000, 0x16ADEB15, 0x69B7800, 0x16ADEC00, 0x2A8),
        _UBISOFT_TEXT1,
        _UBISOFT_EXCEPTIONS,
    ),
    text1=_UBISOFT_TEXT1,
    exception_section=_UBISOFT_EXCEPTIONS,
    exception_directory_size_field=0x17C,
    exception_table_rva=0x1F01BB50,
    exception_table_size=0x57AEB4,
    exception_insert_index=477961,
    relocations={
        # capacity copy sites
        0xC5597C: 0xC4237C,
        0xC5BE63: 0xC48863,
        0xB83DE71: 0xB5062AA,
        # P2P peer table and owner checks
        0xCD1C1F: 0xCBE61F,
        0xBFC5DFA: 0xBC1A70A,
        0xD4F854: 0xD3C254,
        0xD508F1: 0xD3D2F1,
        0xD4F29A: 0xD3BC9A,
        0xD45878: 0xD32278,
        0xD45CDF: 0xD326DF,
        0xD45D6D: 0xD3276D,
        # Storm maxPeers block in the CSession constructor
        0xCD2CF6: 0xCBF6F6,
        # sessions request hook, the JSON helpers it calls and the data they use
        0xC769AF: 0xC633AF,
        0x22FB20: 0x22A730,
        0x22F190: 0x229DA0,
        0x208690: 0x2032E0,
        0x22F14B: 0x229D5B,
        0x6A45958: 0x69AF4D8,
        0x58E1598: 0x58CD748,
        0x58E0638: 0x58CC7E8,
    },
)
BUILDS = {build.name: build for build in (STEAM, UBISOFT)}


def identify_build(sha256: str) -> Build | None:
    return next((build for build in BUILDS.values() if build.sha256 == sha256), None)


def file_offset(rva: int, size: int = 1, build: Build = STEAM) -> int:
    return build.file_offset(rva, size)


# Reference build names kept for the code and tests that only know the Steam layout
ORIGINAL_SHA256 = STEAM.sha256
ORIGINAL_FILE_SIZE = STEAM.file_size
IMAGE_SIZE = STEAM.image_size
XTLS, TLS, TEXT1, EXCEPTION_SECTION = STEAM.sections
SECTIONS = STEAM.sections
EXCEPTION_DIRECTORY_SIZE_FIELD = STEAM.exception_directory_size_field
EXCEPTION_TABLE_RVA = STEAM.exception_table_rva
EXCEPTION_TABLE_SIZE = STEAM.exception_table_size
