"""Minimal read-only access to another Windows process. Never requests write access."""

import ctypes
import functools
import struct
import sys
from ctypes import wintypes


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * wintypes.MAX_PATH),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * wintypes.MAX_PATH),
    ]


@functools.cache
def _kernel32():
    if sys.platform != "win32" or struct.calcsize("P") != 8:
        raise RuntimeError("Use 64-bit Python on Windows")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    for name, entry in (("Process32FirstW", PROCESSENTRY32W), ("Process32NextW", PROCESSENTRY32W),
                        ("Module32FirstW", MODULEENTRY32W), ("Module32NextW", MODULEENTRY32W)):
        function = getattr(k32, name)
        function.argtypes = [wintypes.HANDLE, ctypes.POINTER(entry)]
        function.restype = wintypes.BOOL
    k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
                                      ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.ReadProcessMemory.restype = wintypes.BOOL
    return k32


def _snapshot(k32, flags: int, pid: int, entry_type, first, following):
    handle = k32.CreateToolhelp32Snapshot(flags, pid)
    if not handle or handle == INVALID_HANDLE_VALUE:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    try:
        entry = entry_type()
        entry.dwSize = ctypes.sizeof(entry_type)
        found = first(handle, ctypes.byref(entry))
        while found:
            yield entry
            found = following(handle, ctypes.byref(entry))
    finally:
        k32.CloseHandle(handle)


def find_processes(executable: str) -> list[int]:
    k32 = _kernel32()
    return [entry.th32ProcessID for entry in _snapshot(
        k32, TH32CS_SNAPPROCESS, 0, PROCESSENTRY32W, k32.Process32FirstW, k32.Process32NextW
    ) if entry.szExeFile.lower() == executable.lower()]


def select_process(executable: str, pid: int | None) -> int:
    processes = find_processes(executable)
    if pid is None:
        if len(processes) != 1:
            raise RuntimeError(f"Start one {executable} instance, or select its PID with --pid")
        return processes[0]
    if pid not in processes:
        raise RuntimeError(f"PID {pid} is not a running {executable}")
    return pid


def find_module(pid: int, module: str) -> tuple[int, int, str]:
    k32 = _kernel32()
    for entry in _snapshot(k32, TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid, MODULEENTRY32W,
                           k32.Module32FirstW, k32.Module32NextW):
        if entry.szModule.lower() == module.lower():
            return entry.modBaseAddr, entry.modBaseSize, entry.szExePath
    raise RuntimeError(f"{module} is not loaded in PID {pid}")


class ReadOnlyProcess:
    """Context manager exposing read(address, size) for one process."""

    def __init__(self, pid: int):
        self.pid = pid
        self.k32 = _kernel32()
        self.handle = None

    def __enter__(self):
        self.handle = self.k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), f"Cannot open PID {self.pid} for read-only observation")
        return self

    def __exit__(self, *_):
        self.k32.CloseHandle(self.handle)
        self.handle = None

    def read(self, address: int, size: int) -> bytes:
        buffer = ctypes.create_string_buffer(size)
        count = ctypes.c_size_t()
        if not self.k32.ReadProcessMemory(self.handle, address, buffer, size, ctypes.byref(count)):
            return b""
        return buffer.raw[:count.value]
