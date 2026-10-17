#!/usr/bin/env python3
"""
Far Cry 5 Co-op Patcher — Standalone Windows GUI Application
Provides a native, modern, responsive Windows interface for configuring
Far Cry 5 3-Player (and experimental 4-16 Player) Campaign Co-op and
Cutscene Camera Takeover for extra participants.
"""

import os
import sys
import time
import queue
import threading
from pathlib import Path
from typing import Optional

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import patch_engine as pe

APP_TITLE = "Far Cry 5 — Campaign Co-op Patcher"
APP_VERSION = "v1.1.0"

class CoOpPatcherGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_TITLE} {APP_VERSION}")
        self.root.minsize(740, 720)
        self.root.geometry("800x740")

        # Application state
        self.current_dll_path: Optional[Path] = None
        self.current_info: dict = {}
        self.log_queue = queue.Queue()
        self.is_busy = False
        self.user_manually_toggled_camera = False

        # Configure styles
        self._setup_styles()

        # Build UI layout
        self._build_ui()

        # Start background queue poller and process watcher
        self.root.after(100, self._process_log_queue)
        self.root.after(1000, self._poll_game_process)

        # Initial Auto-Detection
        self.root.after(200, self._initial_detect)

    def _setup_styles(self):
        self.style = ttk.Style()
        available_themes = self.style.theme_names()
        if "vista" in available_themes:
            self.style.theme_use("vista")
        elif "clam" in available_themes:
            self.style.theme_use("clam")

        self.style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"))
        self.style.configure("Subtitle.TLabel", font=("Segoe UI", 9))
        self.style.configure("Header.TLabelframe.Label", font=("Segoe UI", 10, "bold"))
        self.style.configure("Bold.TLabel", font=("Segoe UI", 9, "bold"))
        self.style.configure("Mono.TLabel", font=("Consolas", 8))
        self.style.configure("StatusBadge.TLabel", font=("Segoe UI", 10, "bold"))
        self.style.configure("Action.TButton", font=("Segoe UI", 10, "bold"), padding=6)

    def _build_ui(self):
        main_frame = ttk.Frame(self.root, padding=12)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Header Frame
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        title_lbl = ttk.Label(header_frame, text=APP_TITLE, style="Title.TLabel")
        title_lbl.pack(anchor=tk.W)
        sub_lbl = ttk.Label(
            header_frame,
            text=f"Campaign Co-op Capacity (Tri-Gate) & Cutscene Camera Fix • {APP_VERSION}",
            style="Subtitle.TLabel",
            foreground="#555555",
        )
        sub_lbl.pack(anchor=tk.W)

        # Process Running Alert Banner (Hidden by default)
        self.alert_frame = tk.Frame(main_frame, bg="#f8d7da", relief=tk.SOLID, bd=1)
        self.alert_lbl = tk.Label(
            self.alert_frame,
            text="⚠️ FarCry5.exe is currently running! Please close the game before patching or restoring.",
            bg="#f8d7da",
            fg="#721c24",
            font=("Segoe UI", 9, "bold"),
            pady=4,
        )
        self.alert_lbl.pack(fill=tk.X)

        # 2. Installation Path Frame
        path_group = ttk.LabelFrame(main_frame, text=" Far Cry 5 Game Installation ", padding=10)
        path_group.pack(fill=tk.X, pady=(0, 8))

        path_row = ttk.Frame(path_group)
        path_row.pack(fill=tk.X)

        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(path_row, textvariable=self.path_var, font=("Segoe UI", 9))
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self.btn_auto = ttk.Button(path_row, text="Auto-Detect", command=self.on_auto_detect)
        self.btn_auto.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_browse = ttk.Button(path_row, text="Browse...", command=self.on_browse)
        self.btn_browse.pack(side=tk.LEFT)

        self.platform_lbl = ttk.Label(path_group, text="Platform: Unknown", foreground="#666666")
        self.platform_lbl.pack(anchor=tk.W, pady=(4, 0))

        # 3. Status & Diagnostic Card
        status_group = ttk.LabelFrame(main_frame, text=" Binary Status & Integrity ", padding=10)
        status_group.pack(fill=tk.X, pady=(0, 8))

        # Status badge row
        badge_row = ttk.Frame(status_group)
        badge_row.pack(fill=tk.X, pady=(0, 4))

        ttk.Label(badge_row, text="Current State: ", style="Bold.TLabel").pack(side=tk.LEFT)
        self.status_badge_lbl = ttk.Label(badge_row, text="NOT INSPECTED", style="StatusBadge.TLabel")
        self.status_badge_lbl.pack(side=tk.LEFT)

        # Message row
        self.status_msg_lbl = ttk.Label(status_group, text="Select or auto-detect a Far Cry 5 installation.", wraplength=720)
        self.status_msg_lbl.pack(anchor=tk.W, pady=(0, 4))

        # SHA-256 and Backup status
        hash_row = ttk.Frame(status_group)
        hash_row.pack(fill=tk.X, pady=(2, 0))

        ttk.Label(hash_row, text="SHA-256: ", style="Bold.TLabel").pack(side=tk.LEFT)
        self.sha_lbl = ttk.Label(hash_row, text="N/A", style="Mono.TLabel")
        self.sha_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.backup_lbl = ttk.Label(status_group, text="Backup (.bak): None", foreground="#666666")
        self.backup_lbl.pack(anchor=tk.W, pady=(2, 0))

        # 4. Patch Configuration Frame
        config_group = ttk.LabelFrame(main_frame, text=" Co-op Configuration ", padding=10)
        config_group.pack(fill=tk.X, pady=(0, 8))

        # Row A: Capacity Selector
        cap_row = ttk.Frame(config_group)
        cap_row.pack(fill=tk.X, pady=(0, 4))

        ttk.Label(cap_row, text="Target Capacity: ", style="Bold.TLabel").pack(side=tk.LEFT, padx=(0, 8))

        self.cap_options = [
            f"{n} Players [{pe.CAPACITY_CONFIG[n]['badge']}]" for n in range(2, 17)
        ]
        # Default: 3 Players (index 1)
        self.cap_var = tk.StringVar(value=self.cap_options[1])
        self.cap_combo = ttk.Combobox(
            cap_row,
            textvariable=self.cap_var,
            values=self.cap_options,
            state="readonly",
            width=38,
            font=("Segoe UI", 9),
        )
        self.cap_combo.pack(side=tk.LEFT)
        self.cap_combo.bind("<<ComboboxSelected>>", self._on_capacity_changed)

        # Capacity description label
        self.cap_desc_lbl = ttk.Label(
            config_group,
            text=pe.CAPACITY_CONFIG[3]["description"],
            wraplength=720,
            foreground="#155724",
            font=("Segoe UI", 9, "italic"),
        )
        self.cap_desc_lbl.pack(anchor=tk.W, pady=(2, 6))

        # Row B: Camera Fix Checkbox
        cam_row = ttk.Frame(config_group)
        cam_row.pack(fill=tk.X, pady=(4, 0))

        self.camera_var = tk.BooleanVar(value=True)  # Automatically checked by default!
        self.chk_camera = ttk.Checkbutton(
            cam_row,
            text="Fix Cutscene Cameras (Recommended / Experimental)",
            variable=self.camera_var,
            command=self._on_camera_toggled,
        )
        self.chk_camera.pack(side=tk.LEFT)

        self.cam_sub_lbl = ttk.Label(
            config_group,
            text="Enables cutscene camera takeover for extra players (Players 3 & 4). Recommended for all co-op friends on Windows to prevent camera bugs.",
            wraplength=720,
            foreground="#155724",
            font=("Segoe UI", 8),
        )
        self.cam_sub_lbl.pack(anchor=tk.W, pady=(0, 4))

        # 5. Action Buttons Frame
        action_row = ttk.Frame(main_frame)
        action_row.pack(fill=tk.X, pady=(0, 8))

        self.btn_patch = ttk.Button(
            action_row,
            text="✔  Apply Co-op Patch",
            style="Action.TButton",
            command=self.on_apply_patch,
        )
        self.btn_patch.pack(side=tk.LEFT, padx=(0, 8), fill=tk.X, expand=True)

        self.btn_restore = ttk.Button(
            action_row,
            text="↺  Restore Original Game",
            style="Action.TButton",
            command=self.on_restore,
        )
        self.btn_restore.pack(side=tk.LEFT, padx=(0, 8), fill=tk.X, expand=True)

        self.btn_verify = ttk.Button(
            action_row,
            text="🔍  Verify Files",
            style="Action.TButton",
            command=self.on_verify,
        )
        self.btn_verify.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 6. Activity Log Console
        log_group = ttk.LabelFrame(main_frame, text=" Activity Log ", padding=8)
        log_group.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(
            log_group,
            wrap=tk.WORD,
            font=("Consolas", 8),
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="white",
            relief=tk.FLAT,
            height=10,
        )
        self.log_scroll = ttk.Scrollbar(log_group, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=self.log_scroll.set)

        self.log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Tags for colored logging
        self.log_text.tag_configure("INFO", foreground="#9cdcfe")
        self.log_text.tag_configure("SUCCESS", foreground="#4ec9b0")
        self.log_text.tag_configure("WARNING", foreground="#ce9178")
        self.log_text.tag_configure("ERROR", foreground="#f44747")

        # Bottom utility buttons
        bottom_row = ttk.Frame(main_frame)
        bottom_row.pack(fill=tk.X, pady=(4, 0))

        ttk.Button(bottom_row, text="Clear Log", command=self._clear_log).pack(side=tk.RIGHT)
        ttk.Button(bottom_row, text="Copy Log", command=self._copy_log).pack(side=tk.RIGHT, padx=(0, 4))

    # ==========================================================================
    # Background Threading & Queue Processing
    # ==========================================================================

    def _log(self, message: str, level: str = "INFO"):
        self.log_queue.put((message, level))

    def _process_log_queue(self):
        while not self.log_queue.empty():
            msg, level = self.log_queue.get_nowait()
            ts = time.strftime("%H:%M:%S")
            line = f"[{ts}] [{level:<7}] {msg}\n"
            self.log_text.insert(tk.END, line, level)
            self.log_text.see(tk.END)
        self.root.after(100, self._process_log_queue)

    def _set_busy(self, busy: bool):
        self.is_busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        self.btn_patch.configure(state=state)
        self.btn_restore.configure(state=state)
        self.btn_verify.configure(state=state)
        self.btn_auto.configure(state=state)
        self.btn_browse.configure(state=state)

    def _run_threaded(self, target_func, *args):
        if self.is_busy:
            return
        self._set_busy(True)

        def worker():
            try:
                target_func(*args)
            except Exception as e:
                self._log(f"Unexpected error: {e}", "ERROR")
            finally:
                self.root.after(0, lambda: self._set_busy(False))
                self.root.after(0, self._refresh_ui_status)

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    # ==========================================================================
    # Real-Time Process Monitor
    # ==========================================================================

    def _poll_game_process(self):
        try:
            running = pe.is_game_running()
            if running:
                if not self.alert_frame.winfo_ismapped():
                    self.alert_frame.pack(fill=tk.X, pady=(0, 8), before=self.path_entry.master.master)
            else:
                if self.alert_frame.winfo_ismapped():
                    self.alert_frame.pack_forget()
        except Exception:
            pass
        self.root.after(1500, self._poll_game_process)

    # ==========================================================================
    # Capacity Selection Handler
    # ==========================================================================

    def _on_capacity_changed(self, event=None):
        selected_str = self.cap_var.get()
        try:
            n = int(selected_str.split()[0])
            cfg = pe.CAPACITY_CONFIG.get(n, {})
            desc = cfg.get("description", "")
            badge = cfg.get("badge", "")
            tier = cfg.get("tier", "")

            color = "#155724" if tier in ("VERIFIED", "ORIGINAL") else "#856404"
            self.cap_desc_lbl.configure(text=f"[{badge}] {desc}", foreground=color)
        except Exception:
            pass

    def _on_camera_toggled(self):
        self.user_manually_toggled_camera = True
        checked = self.camera_var.get()
        state_str = "Enabled" if checked else "Disabled"
        self._log(f"Cutscene camera fix option set to: {state_str}", "INFO")
        if not checked:
            self._log("Notice: Cutscene Camera Fix disabled. Additional players (Players 3 & 4) will experience disrupted cutscene cameras unless patched locally.", "WARNING")

    def get_selected_capacity(self) -> int:
        selected_str = self.cap_var.get()
        try:
            return int(selected_str.split()[0])
        except Exception:
            return 3

    # ==========================================================================
    # Installation & Inspection Logic
    # ==========================================================================

    def _initial_detect(self):
        self._log("Starting Far Cry 5 installation auto-detection...", "INFO")
        installs = pe.detect_installations()
        if installs:
            first = installs[0]
            self.set_active_dll(first.dll_path, first.platform_hint)
            self._log(f"Auto-detected installation: {first.root_dir} ({first.platform_hint})", "SUCCESS")
        else:
            self._log("No default installation detected in standard locations or registry.", "WARNING")
            self._log("Please click 'Browse...' to locate your Far Cry 5 folder or bin/FC_m64.dll.", "INFO")

    def set_active_dll(self, dll_path: Path, platform_hint: str = "Manual"):
        self.current_dll_path = dll_path
        self.path_var.set(str(dll_path))
        self.platform_lbl.configure(text=f"Platform: {platform_hint}")
        self._inspect_and_update()

    def _inspect_and_update(self):
        if not self.current_dll_path or not self.current_dll_path.exists():
            self.status_badge_lbl.configure(text="NOT FOUND", foreground="#dc3545")
            self.status_msg_lbl.configure(text="The specified FC_m64.dll file was not found.")
            self.sha_lbl.configure(text="N/A")
            self.backup_lbl.configure(text="Backup: N/A")
            return

        self._run_threaded(self._worker_inspect)

    def _worker_inspect(self):
        self._log(f"Inspecting binary: {self.current_dll_path}", "INFO")
        info = pe.inspect_binary(self.current_dll_path)
        self.current_info = info
        cam_info = "Applied" if info.get("camera_fix_applied") else "Not Applied"
        self._log(f"Status: {info['status']} | Capacity: {info.get('capacity')}P | Camera Fix: {cam_info} | SHA-256: {info['sha256']}", "INFO")

    def _refresh_ui_status(self):
        info = self.current_info
        if not info or not info.get("exists"):
            return

        status = info.get("status", "UNKNOWN")
        sha = info.get("sha256", "N/A")
        msg = info.get("message", "")
        cap = info.get("capacity")
        cam_applied = info.get("camera_fix_applied", False)

        # Synchronize UI checkbox:
        # If binary already has camera fix, keep checked.
        # If user has not manually interacted with the checkbox, keep it checked by default!
        if cam_applied:
            self.camera_var.set(True)
        elif not self.user_manually_toggled_camera:
            self.camera_var.set(True)
        else:
            self.camera_var.set(self.camera_var.get())

        # Synchronize capacity selector if detected
        if cap in range(2, 17):
            for opt in self.cap_options:
                if opt.startswith(f"{cap} Players"):
                    self.cap_var.set(opt)
                    self._on_capacity_changed()
                    break

        # Format Badge
        if status == "ORIGINAL_PRISTINE":
            self.status_badge_lbl.configure(text="PRISTINE (2 Players)", foreground="#0d6efd")
        elif status == "ORIGINAL_CAM_FIX":
            self.status_badge_lbl.configure(text="PRISTINE (2P) + CAMERA FIX", foreground="#198754")
        elif status == "PATCHED_TRI_GATE":
            badge_text = f"TRI-GATE PATCHED ({cap} Players)"
            color = "#198754" if cap == 3 else "#fd7e14"
            self.status_badge_lbl.configure(text=badge_text, foreground=color)
        elif status == "PATCHED_TRI_GATE_CAM":
            badge_text = f"TRI-GATE ({cap}P) + CAMERA FIX"
            color = "#198754" if cap == 3 else "#fd7e14"
            self.status_badge_lbl.configure(text=badge_text, foreground=color)
        elif status == "PATCHED_TRI_V1":
            self.status_badge_lbl.configure(text="TRI-GATE V1 (Needs Upgrade)", foreground="#ffc107")
        elif status.startswith("PATCHED_"):
            cam_tag = " + CAM" if cam_applied else ""
            self.status_badge_lbl.configure(text=f"{status} ({cap}P){cam_tag}", foreground="#ffc107")
        else:
            self.status_badge_lbl.configure(text="UNKNOWN / MODIFIED", foreground="#dc3545")

        self.status_msg_lbl.configure(text=msg)
        self.sha_lbl.configure(text=sha)

        # Backup status
        if info.get("backup_exists"):
            if info.get("backup_valid"):
                self.backup_lbl.configure(text=f"Backup (.bak): Verified Pristine Original (SHA: {info.get('backup_sha')[:16]}...)", foreground="#198754")
            else:
                self.backup_lbl.configure(text="Backup (.bak): CORRUPT / MISMATCHED", foreground="#dc3545")
        else:
            self.backup_lbl.configure(text="Backup (.bak): None created yet (will be created automatically on first patch)", foreground="#666666")

    # ==========================================================================
    # UI Actions
    # ==========================================================================

    def on_auto_detect(self):
        self._initial_detect()

    def on_browse(self):
        selected = filedialog.askopenfilename(
            title="Select Far Cry 5 FC_m64.dll or FarCry5.exe",
            filetypes=[("Far Cry 5 Files", "FC_m64.dll;FarCry5.exe"), ("All Files", "*.*")],
        )
        if not selected:
            folder = filedialog.askdirectory(title="Or Select Far Cry 5 Game Folder")
            if folder:
                dll = Path(folder) / "bin" / "FC_m64.dll"
                if dll.exists():
                    self.set_active_dll(dll, "Manual (Folder)")
                    return
                else:
                    messagebox.showerror("File Not Found", f"Could not find bin/FC_m64.dll in {folder}")
            return

        p = Path(selected)
        if p.name.lower() == "farcry5.exe":
            dll = p.parent / "FC_m64.dll"
            if not dll.exists():
                dll = p.parent / "bin" / "FC_m64.dll"
        else:
            dll = p

        if dll.exists():
            self.set_active_dll(dll, "Manual (File)")
        else:
            messagebox.showerror("File Not Found", f"Could not locate FC_m64.dll corresponding to {selected}")

    def on_apply_patch(self):
        if pe.is_game_running():
            messagebox.showerror(
                "Game is Running",
                "FarCry5.exe is currently running!\n\nPlease completely exit Far Cry 5 before applying the co-op patch.",
            )
            return

        if not self.current_dll_path or not self.current_dll_path.exists():
            messagebox.showerror("Invalid Path", "Please select a valid FC_m64.dll binary.")
            return

        cap = self.get_selected_capacity()
        cam_fix = self.camera_var.get()

        # Warning when Cutscene Camera Fix is disabled
        if not cam_fix:
            confirm_cam = messagebox.askyesno(
                "Cutscene Camera Warning",
                "You have unchecked 'Fix Cutscene Cameras'.\n\n"
                "⚠️ Notice regarding cinematic camera behavior:\n\n"
                "• Without this patch, additional players (Players 3 and 4) will experience disrupted cutscenes during story missions and outpost liberations. They will hear audio and dialogue, but their camera will remain stuck in first-person gameplay view instead of switching to the cinematic scene.\n\n"
                "• For cutscenes to work properly without bugs, EVERY participating friend in your co-op session must apply this patch locally on their own game installation.\n\n"
                "Are you sure you want to proceed without the Cutscene Camera Fix?",
                icon="warning",
            )
            if not confirm_cam:
                return

        if cap > 3:
            confirm = messagebox.askyesno(
                "Experimental Capacity",
                f"You have selected {cap} Players.\n\n"
                f"Note: 3-player co-op is the verified and fully proven baseline.\n"
                f"{cap}-player co-op synchronizes the internal Tri-Gate capacity, but has not been verified in extensive gameplay.\n\n"
                f"Do you wish to proceed?",
            )
            if not confirm:
                return

        def worker():
            ok = pe.apply_patch(
                self.current_dll_path,
                players=cap,
                camera_fix=cam_fix,
                callback=self._log,
            )
            if ok:
                cam_msg = "with Cutscene Camera Fix" if cam_fix else "without Camera Fix"
                self._log("Configuration complete! Start Far Cry 5 and enjoy co-op.", "SUCCESS")
                self.root.after(0, lambda: messagebox.showinfo(
                    "Patch Successful",
                    f"Configuration successfully applied for {cap} players ({cam_msg})!\n\n"
                    f"A verified backup of your pristine game binary is preserved.\n"
                    f"Launch Far Cry 5 to play.",
                ))
            else:
                self.root.after(0, lambda: messagebox.showerror(
                    "Patch Failed",
                    "The patch operation could not be completed.\n"
                    "Please check the Activity Log for details.",
                ))

        self._run_threaded(worker)

    def on_restore(self):
        if pe.is_game_running():
            messagebox.showerror(
                "Game is Running",
                "FarCry5.exe is currently running!\n\nPlease completely exit Far Cry 5 before restoring.",
            )
            return

        if not self.current_dll_path or not self.current_dll_path.exists():
            messagebox.showerror("Invalid Path", "Please select a valid FC_m64.dll binary.")
            return

        confirm = messagebox.askyesno(
            "Restore Original Game",
            "This will restore your Far Cry 5 installation to the official pristine 2-player state.\n\nProceed?",
        )
        if not confirm:
            return

        def worker():
            ok = pe.restore_original(
                self.current_dll_path,
                callback=self._log,
            )
            if ok:
                self.root.after(0, lambda: messagebox.showinfo(
                    "Restoration Complete",
                    "Your Far Cry 5 installation has been restored to the official pristine original state.",
                ))
            else:
                self.root.after(0, lambda: messagebox.showerror(
                    "Restoration Failed",
                    "Restoration could not be completed. Check Activity Log.",
                ))

        self._run_threaded(worker)

    def on_verify(self):
        self._inspect_and_update()

    def _clear_log(self):
        self.log_text.delete("1.0", tk.END)

    def _copy_log(self):
        content = self.log_text.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        messagebox.showinfo("Copied", "Activity log copied to clipboard.")

def main():
    try:
        root = tk.Tk()
        app = CoOpPatcherGUI(root)
        root.mainloop()
    except Exception as e:
        import traceback
        err_msg = traceback.format_exc()
        try:
            from tkinter import messagebox
            messagebox.showerror("Fatal Error", f"Failed to start Far Cry 5 Co-op Patcher:\n\n{err_msg}")
        except Exception:
            pass
        sys.exit(1)

if __name__ == "__main__":
    main()
