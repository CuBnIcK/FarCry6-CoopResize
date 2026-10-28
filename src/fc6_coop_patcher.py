"""Far Cry 6 co-op patcher for players: one window, install and restore.

Without arguments it opens the window. --status, --install and --restore do the same
from a terminal, with the game folder as the argument or auto-detected.
"""

import argparse
import queue
import sys
import threading
from pathlib import Path

from fc6.install import find_dll, find_installations, game_running, inspect, install, restore
from fc6.variants import ORIGINAL

APP_TITLE = "Far Cry 6 Co-op Resize"
APP_VERSION = "1.0.0"
NOTICE = ("Every player in the group installs the patch. 3 players are tested, "
          "4 players work at your own risk. Close Far Cry 6 before installing or restoring.")


def describe(dll: Path) -> str:
    state = inspect(dll)
    if state.build is None:
        return "Unsupported game version (verify the game files, or wait for a patch update)"
    platform = "Steam" if state.build.name == "steam" else "Ubisoft Connect"
    if state.variant is ORIGINAL:
        return f"{platform} - original game, 2 players"
    if state.variant.name == "peer-owner":
        return f"{platform} - co-op patch installed, up to 4 players"
    return f"{platform} - older experimental patch ({state.variant.name}), install to update"


def run_gui() -> int:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title(f"{APP_TITLE} {APP_VERSION}")
    root.minsize(560, 0)
    results = queue.Queue()
    busy = tk.BooleanVar(value=False)

    frame = ttk.Frame(root, padding=14)
    frame.pack(fill=tk.BOTH, expand=True)
    ttk.Label(frame, text=APP_TITLE, font=("Segoe UI", 14, "bold")).pack(anchor=tk.W)
    ttk.Label(frame, text=NOTICE, wraplength=530, foreground="#555555").pack(anchor=tk.W, pady=(2, 10))

    ttk.Label(frame, text="Far Cry 6 folder").pack(anchor=tk.W)
    row = ttk.Frame(frame)
    row.pack(fill=tk.X, pady=(2, 8))
    folder = tk.StringVar()
    folders = ttk.Combobox(row, textvariable=folder)
    folders.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

    status = tk.StringVar(value="Looking for Far Cry 6...")
    ttk.Label(frame, textvariable=status, font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))

    buttons = ttk.Frame(frame)
    buttons.pack(fill=tk.X)
    install_button = ttk.Button(buttons, text="Install co-op patch")
    install_button.pack(side=tk.LEFT, padx=(0, 6))
    restore_button = ttk.Button(buttons, text="Restore original")
    restore_button.pack(side=tk.LEFT)
    progress = ttk.Progressbar(buttons, mode="indeterminate", length=140)

    def in_background(work, done):
        busy.set(True)
        for widget in (install_button, restore_button, folders, browse):
            widget.state(["disabled"])
        progress.pack(side=tk.RIGHT)
        progress.start(12)

        def worker():
            try:
                results.put((done, work(), None))
            except Exception as error:  # shown to the player, the window must stay usable
                results.put((done, None, error))
        threading.Thread(target=worker, daemon=True).start()

    def poll():
        try:
            done, value, error = results.get_nowait()
        except queue.Empty:
            root.after(100, poll)
            return
        progress.stop()
        progress.pack_forget()
        for widget in (install_button, restore_button, folders, browse):
            widget.state(["!disabled"])
        busy.set(False)
        done(value, error)
        root.after(100, poll)

    def selected_dll() -> Path | None:
        try:
            return find_dll(Path(folder.get().strip()))
        except (FileNotFoundError, OSError):
            return None

    def refresh(*_):
        if busy.get():
            return
        dll = selected_dll()
        if dll is None:
            status.set("Choose the Far Cry 6 folder (the one that contains bin)")
            return
        status.set("Checking the game DLL...")
        in_background(lambda: describe(dll), lambda text, error: status.set(text if error is None else str(error)))

    def run_action(action, title):
        dll = selected_dll()
        if dll is None:
            messagebox.showerror(title, "Choose the Far Cry 6 folder first")
            return
        if game_running():
            messagebox.showerror(title, "Far Cry 6 is running. Close the game and try again.")
            return
        status.set("Working, this takes up to a minute...")

        def done(message, error):
            if error is None:
                messagebox.showinfo(title, message)
            else:
                messagebox.showerror(title, str(error))
            refresh()
        in_background(lambda: action(dll), done)

    def on_browse():
        chosen = filedialog.askdirectory(title="Choose the Far Cry 6 folder")
        if chosen:
            folder.set(chosen)
            refresh()

    browse = ttk.Button(row, text="Browse...", command=on_browse)
    browse.pack(side=tk.LEFT)
    install_button.configure(command=lambda: run_action(install, "Install co-op patch"))
    restore_button.configure(command=lambda: run_action(restore, "Restore original"))
    for event in ("<<ComboboxSelected>>", "<Return>", "<FocusOut>"):
        folders.bind(event, refresh)

    def detected(found, error):
        folders["values"] = [str(path) for path in found or ()]
        if found:
            folder.set(str(found[0]))
            refresh()
        else:
            status.set("Far Cry 6 was not found automatically, use Browse...")
    in_background(find_installations, detected)
    root.after(100, poll)
    root.mainloop()
    return 0


def run_cli(args) -> int:
    try:
        if args.folder is None:
            found = find_installations()
            if not found:
                raise FileNotFoundError("Far Cry 6 was not found automatically, pass the game folder")
            args.folder = found[0]
        dll = find_dll(args.folder)
        print(dll)
        if args.status:
            print(describe(dll))
            return 0
        if game_running():
            raise RuntimeError("Far Cry 6 is running, close the game first")
        print(install(dll) if args.install else restore(dll))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=f"{APP_TITLE}. {NOTICE}")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--status", action="store_true", help="Show which DLL is installed")
    actions.add_argument("--install", action="store_true", help="Install the co-op patch")
    actions.add_argument("--restore", action="store_true", help="Put the original DLL back")
    parser.add_argument("folder", type=Path, nargs="?", help="Far Cry 6 folder, auto-detected when omitted")
    args = parser.parse_args()
    if args.status or args.install or args.restore:
        return run_cli(args)
    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
