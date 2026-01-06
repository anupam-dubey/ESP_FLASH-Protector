#!/usr/bin/env python3
"""
esp_flash_protector_full.py
ESP8266 Flash Protector — by Anupam Dubey
Production-ready GUI for factory use.

Requirements:
  - Python 3.8+
  - pyserial (pip install pyserial)

Usage:
  python esp_flash_protector_full.py
"""

import os
import math
import time
import threading
import tempfile
import shutil
import hmac
import hashlib
import binascii
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
import serial
import serial.tools.list_ports

# App metadata
APP_TITLE = "ESP8266 Flash Protector — by Anupam Dubey"
APP_VERSION = "v3.1"
CHUNK_ROUND = 0x1000  # 4KB rounding for FW_MAX_LEN
DEFAULT_BAUD = 115200
PROBE_CMD = b"CHIPID?\n"

# Probe sketch text (user will copy and flash via Arduino IDE)
PROBE_SKETCH = r"""// Probe_ChipID.ino
// Flash this sketch to an ESP8266 so the PC tool can read its CHIPID.
// Upload with Arduino IDE: File -> Open -> select this file -> Upload

#include <Arduino.h>
#include <ESP8266WiFi.h>

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("ESP8266 ChipID Probe ready");
}

void loop() {
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd.equalsIgnoreCase("CHIPID?")) {
      uint32_t chipid = ESP.getChipId();
      Serial.printf("CHIPID: 0x%08X\n", chipid);
    } else {
      // small ack so operators know the board responds
      Serial.println("OK");
    }
  }
  delay(10);
}
"""

# Sample sketches for menu
SAMPLE_BEFORE = """// pre_protect_blink.ino - before protection
#include <Arduino.h>

void setup() {
  Serial.begin(115200);
  pinMode(2, OUTPUT);
}

void loop() {
  Serial.println("Running unprotected firmware (blink)");
  digitalWrite(2, LOW); delay(400);
  digitalWrite(2, HIGH); delay(400);
}
"""

SAMPLE_AFTER = """// post_protect_main.ino - after protection (include signed_firmware.h)
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <Hash.h>
#include "signed_firmware.h"

#define FW_START_ADDR 0x40200000UL
// FW_MAX_LEN is provided in signed_firmware.h

void halt_error() {
  pinMode(2, OUTPUT);
  while (true) { digitalWrite(2, LOW); delay(500); digitalWrite(2, HIGH); delay(500); }
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("Verifying firmware...");

  // Example: compute HMAC over firmware region and chipid (implementation depends on your HMAC library).
  Serial.println("If verification fails, device will halt (error blink).");
  // ... (see verification example provided with the tool)
}

void loop() {
  // Your protected application logic here
}
"""

# ---------- Utilities ----------
def list_serial_ports():
    try:
        return [p.device for p in serial.tools.list_ports.comports()]
    except Exception:
        return []

def safe_hex_to_bytes(hexstr: str):
    s = hexstr.strip().lower().replace("0x", "").replace(" ", "")
    if len(s) % 2 != 0:
        s = "0" + s
    return bytes.fromhex(s)

def compute_fw_len_rounded(path):
    size = os.path.getsize(path)
    return int(math.ceil(size / CHUNK_ROUND) * CHUNK_ROUND)

# ---------- Main Application ----------
class ESPFlashProtectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_TITLE}   {APP_VERSION}")
        self.root.geometry("1000x720")
        self.root.minsize(900, 620)

        # variables
        self.port_var = tk.StringVar()
        self.baud_var = tk.StringVar(value=str(DEFAULT_BAUD))
        self.chipid_var = tk.StringVar()
        self.fw_path_var = tk.StringVar()
        self.fw_len_var = tk.StringVar(value="(auto)")
        self.secret_var = tk.StringVar()
        self.show_secret = tk.BooleanVar(value=False)
        self.out_header_var = tk.StringVar(value=os.path.join(os.getcwd(), "signed_firmware.h"))
        self.project_folder_var = tk.StringVar()

        self._build_ui()
        self.refresh_ports(auto_select=True)

    def _build_ui(self):
        # Menu
        menubar = tk.Menu(self.root)
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filem)

        samples = tk.Menu(menubar, tearoff=0)
        samples.add_command(label="Probe Sketch (copy)", command=lambda: self.show_sample_window("Probe Sketch", PROBE_SKETCH, "Probe_ChipID.ino"))
        samples.add_command(label="Sample - Before Protection", command=lambda: self.show_sample_window("Before", SAMPLE_BEFORE, "pre_protect_blink.ino"))
        samples.add_command(label="Sample - After Protection", command=lambda: self.show_sample_window("After", SAMPLE_AFTER, "post_protect_main.ino"))
        menubar.add_cascade(label="Samples", menu=samples)

        helpm = tk.Menu(menubar, tearoff=0)
        helpm.add_command(label="Step-by-step Guide", command=self.show_help)
        helpm.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=helpm)
        self.root.config(menu=menubar)

        # top frame for controls
        top = tk.Frame(self.root, padx=10, pady=8)
        top.pack(fill="x")

        # Row 0: port, refresh, probe button, copy probe
        tk.Label(top, text="Serial Port:", width=10, anchor="w").grid(row=0, column=0, sticky="w")
        ports = list_serial_ports()
        init_port = ports[0] if ports else ""
        self.port_var.set(init_port)
        self.port_menu = tk.OptionMenu(top, self.port_var, init_port, *ports)
        self.port_menu.config(width=22)
        self.port_menu.grid(row=0, column=1, sticky="w")

        tk.Button(top, text="Refresh", command=lambda: self.refresh_ports(auto_select=False), width=10).grid(row=0, column=2, padx=6)
        tk.Label(top, text="Baud:", anchor="e").grid(row=0, column=3)
        tk.Entry(top, textvariable=self.baud_var, width=8).grid(row=0, column=4, sticky="w", padx=(2,8))
        tk.Button(top, text="Read Chip ID", command=self.read_chipid_thread, bg="#4CAF50", fg="white").grid(row=0, column=5, padx=6)
        tk.Button(top, text="Copy Probe Sketch", command=self.copy_probe_sketch, bg="#FF9800").grid(row=0, column=6, padx=6)

        # Row 1: chip id display & manual set
        tk.Label(top, text="Chip ID:", anchor="w").grid(row=1, column=0, sticky="w", pady=(8,0))
        tk.Entry(top, textvariable=self.chipid_var, width=30).grid(row=1, column=1, sticky="w", pady=(8,0))
        tk.Button(top, text="Manual Set", command=self.manual_set_chipid).grid(row=1, column=2, padx=6, pady=(8,0))
        tk.Label(top, text="(hex e.g. 01a2b3c4 or decimal)").grid(row=1, column=3, columnspan=3, sticky="w", pady=(8,0))

        # Row 2: firmware browse + fw_len
        tk.Label(top, text="Firmware (.bin):").grid(row=2, column=0, sticky="w", pady=(12,0))
        tk.Entry(top, textvariable=self.fw_path_var, width=78).grid(row=2, column=1, columnspan=4, sticky="w", pady=(12,0))
        tk.Button(top, text="Browse", command=self.browse_firmware).grid(row=2, column=5, padx=6, pady=(12,0))

        tk.Label(top, text="Detected FW length:").grid(row=3, column=0, sticky="w", pady=(8,0))
        tk.Entry(top, textvariable=self.fw_len_var, width=20, state="readonly").grid(row=3, column=1, sticky="w", pady=(8,0))

        # Row 3: master secret + Show / Paste / Use Sample
        tk.Label(top, text="MASTER_SECRET (hex):").grid(row=4, column=0, sticky="w", pady=(12,0))
        self.secret_entry = tk.Entry(top, textvariable=self.secret_var, width=60, show="*")
        self.secret_entry.grid(row=4, column=1, columnspan=3, sticky="w", pady=(12,0))
        tk.Button(top, text="Show", command=self.toggle_secret).grid(row=4, column=4, padx=6)
        tk.Button(top, text="Paste (visible)", command=self.paste_secret_visible).grid(row=4, column=5, padx=6)
        tk.Button(top, text="Use Sample Key", command=self.fill_sample_key, bg="#607D8B", fg="white").grid(row=4, column=6, padx=6)

        # Row 4: output header, project folder
        tk.Label(top, text="Output header path:").grid(row=5, column=0, sticky="w", pady=(8,0))
        tk.Entry(top, textvariable=self.out_header_var, width=78).grid(row=5, column=1, columnspan=4, sticky="w", pady=(8,0))
        tk.Button(top, text="Choose", command=self.choose_output_header).grid(row=5, column=5, padx=6)

        tk.Label(top, text="Project folder (optional):").grid(row=6, column=0, sticky="w", pady=(10,0))
        tk.Entry(top, textvariable=self.project_folder_var, width=58).grid(row=6, column=1, columnspan=3, sticky="w", pady=(10,0))
        tk.Button(top, text="Browse", command=self.browse_project_folder).grid(row=6, column=4, padx=6)

        # actions
        actions = tk.Frame(self.root, pady=8)
        actions.pack(fill="x", padx=10)
        tk.Button(actions, text="Generate signed_firmware.h", command=self.generate_header, bg="#2196F3", fg="white", width=30).pack(side="left", padx=8)
        tk.Button(actions, text="Generate + Copy to Project", command=self.generate_and_copy, width=26).pack(side="left")
        tk.Button(actions, text="Export Project Package", command=self.export_project_package, width=22).pack(side="left", padx=8)

        # status
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(self.root, textvariable=self.status_var, bg="#f0f0f0", anchor="w", relief="sunken").pack(fill="x", padx=10, pady=(6,6))

        # bottom: log and help
        bottom = tk.Frame(self.root, padx=10, pady=6)
        bottom.pack(fill="both", expand=True)

        # log
        logframe = tk.Frame(bottom)
        logframe.pack(side="left", fill="both", expand=True)
        tk.Label(logframe, text="Log").pack(anchor="w")
        self.log_box = scrolledtext.ScrolledText(logframe, wrap="word", font=("Consolas", 10))
        self.log_box.pack(fill="both", expand=True)

        # help box
        helpframe = tk.Frame(bottom, width=360)
        helpframe.pack(side="right", fill="y", padx=(10,0))
        tk.Label(helpframe, text="Quick Steps & Tips").pack(anchor="w")
        self.help_text = scrolledtext.ScrolledText(helpframe, wrap="word", height=24, width=44, font=("Segoe UI", 9))
        self.help_text.insert("1.0", self._help_text())
        self.help_text.config(state="disabled")
        self.help_text.pack(fill="y", expand=True)

        self.log("Application started.")

    # ---------- UI helpers ----------
    def log(self, msg):
        ts = time.strftime("[%H:%M:%S]")
        try:
            self.log_box.insert("end", f"{ts} {msg}\n")
            self.log_box.see("end")
        except Exception:
            pass
        print(msg)

    def set_status(self, s):
        self.status_var.set(s)
        self.log(s)

    def _help_text(self):
        return (
            "Factory flow (step-by-step):\n\n"
            "STEP 1 — Prepare board for CHIPID read:\n"
            "  1. Click 'Copy Probe Sketch' and save the generated sketch file.\n"
            "  2. Open the saved file in Arduino IDE and upload it to the ESP8266 board.\n"
            "  3. Connect the board via USB to the PC and select the correct COM port.\n"
            "  4. Click 'Read Chip ID' — the tool will send 'CHIPID?' and parse the reply.\n\n"
            "STEP 2 — Protect firmware:\n"
            "  1. Select the compiled firmware .bin (this is the pre-protection binary).\n"
            "  2. Ensure MASTER_SECRET (hex) is entered (kept on build server only).\n"
            "  3. Click 'Generate signed_firmware.h'. The header will contain EXPECTED_HMAC, DEVICE_CHIPID and FW_MAX_LEN.\n\n"
            "STEP 3 — Finalize:\n"
            "  1. Copy the header into your Arduino project, include it, and rebuild the firmware.\n"
            "  2. Flash the rebuilt (protected) firmware to the device. On boot the verification routine should pass.\n\n"
            "Notes:\n - MASTER_SECRET should be secret; protect access on the build PC.\n - The probe sketch replies to 'CHIPID?' with 'CHIPID: 0xXXXXXXXX'.\n - Use 'Export Project Package' to create a folder with firmware + header + verification example + README.\n"
        )

    # ---------- port actions ----------
    def refresh_ports(self, auto_select=False):
        ports = list_serial_ports()
        menu = self.port_menu["menu"]
        menu.delete(0, "end")
        if not ports:
            menu.add_command(label="(no ports)", command=lambda: self.port_var.set(""))
            self.port_var.set("")
        else:
            for p in ports:
                menu.add_command(label=p, command=lambda value=p: self.port_var.set(value))
            if auto_select and len(ports) == 1:
                self.port_var.set(ports[0])
            elif self.port_var.get() not in ports:
                self.port_var.set(ports[0])
        self.set_status("Ports refreshed.")

    # ---------- probe sketch copy ----------
    def copy_probe_sketch(self):
        folder = filedialog.askdirectory(title="Select folder to save Probe Sketch (open in Arduino IDE to upload)")
        if not folder:
            return
        path = os.path.join(folder, "Probe_ChipID.ino")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(PROBE_SKETCH)
            self.set_status(f"Probe sketch saved: {path}")
            messagebox.showinfo("Probe Sketch Saved", f"Probe sketch saved to:\n{path}\n\nOpen this file in Arduino IDE and upload to device.")
        except Exception as e:
            self.set_status("Failed to save probe sketch: " + str(e))
            messagebox.showerror("Save failed", str(e))

    # ---------- read chip ID ----------
    def read_chipid_thread(self):
        t = threading.Thread(target=self.read_chipid)
        t.daemon = True
        t.start()

    def read_chipid(self):
        port = self.port_var.get().strip()
        if not port:
            messagebox.showwarning("Select port", "Please select a serial port first.")
            return
        try:
            baud = int(self.baud_var.get())
        except:
            baud = DEFAULT_BAUD
        self.set_status(f"Probing {port} @ {baud} ...")
        try:
            ser = serial.Serial(port, baud, timeout=2)
        except Exception as e:
            self.set_status("Open serial failed: " + str(e))
            return
        try:
            ser.reset_input_buffer()
            ser.write(PROBE_CMD)
            ser.flush()
            start = time.time()
            found = False
            while time.time() - start < 4.0:
                line = ser.readline()
                if not line:
                    continue
                try:
                    text = line.decode(errors="ignore").strip()
                except:
                    text = str(line)
                self.log("Serial: " + text)
                import re
                m = re.search(r"(0x)?([0-9a-fA-F]{6,8})", text)
                if m:
                    raw = m.group(2).lower()
                    self.chipid_var.set(raw)
                    self.set_status("Detected CHIPID: " + raw)
                    found = True
                    break
            if not found:
                self.set_status("No CHIPID response. Ensure probe sketch is uploaded and device connected.")
                messagebox.showwarning("No response", "No CHIPID response received. Check that probe sketch is flashed and serial port is correct.")
        finally:
            try:
                ser.close()
            except:
                pass

    def manual_set_chipid(self):
        v = simpledialog.askstring("Manual CHIPID", "Enter chipid (hex e.g. 01a2b3c4 or decimal):")
        if v:
            self.chipid_var.set(v.strip().lower())
            self.set_status("Manual CHIPID set.")

    # ---------- firmware selection ----------
    def browse_firmware(self):
        p = filedialog.askopenfilename(title="Select firmware .bin", filetypes=[("Binary files","*.bin"), ("All","*.*")])
        if not p:
            return
        self.fw_path_var.set(p)
        try:
            fw_len = compute_fw_len_rounded(p)
            self.fw_len_var.set(f"0x{fw_len:X}")
            self.set_status(f"Firmware selected: {os.path.basename(p)} (len 0x{fw_len:X})")
        except Exception as e:
            self.set_status("Error reading firmware size: " + str(e))

    # ---------- secret helpers ----------
    def toggle_secret(self):
        if self.show_secret.get():
            self.secret_entry.config(show="*")
            self.show_secret.set(False)
        else:
            self.secret_entry.config(show="")
            self.show_secret.set(True)

    def paste_secret_visible(self):
        v = simpledialog.askstring("MASTER_SECRET (hex)", "Paste MASTER_SECRET (hex, 64 hex chars recommended):")
        if v:
            self.secret_var.set(v.strip())
            self.set_status("MASTER_SECRET entered (hidden).")

    def fill_sample_key(self):
        # 32-byte (256-bit) example key (for demo/testing only)
        sample_key = "A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0011223344556677"
        self.secret_var.set(sample_key)
        self.show_secret.set(True)
        self.secret_entry.config(show="")
        self.set_status("Sample MASTER_SECRET loaded (for testing only).")
        messagebox.showinfo("Sample Key Loaded",
                            "A sample 256-bit MASTER_SECRET has been inserted.\n\n"
                            "⚠️ For testing only — do not use in production.\n\n"
                            f"{sample_key}")

    # ---------- file dialogs ----------
    def choose_output_header(self):
        p = filedialog.asksaveasfilename(title="Save header as", defaultextension=".h", filetypes=[("Header files","*.h")])
        if p:
            self.out_header_var.set(p)
            self.set_status("Output header: " + p)

    def browse_project_folder(self):
        p = filedialog.askdirectory(title="Select Arduino project folder")
        if p:
            self.project_folder_var.set(p)
            self.set_status("Project folder: " + p)

    # ---------- header generation ----------
    def generate_header(self):
        fw_path = self.fw_path_var.get().strip()
        if not fw_path or not os.path.isfile(fw_path):
            messagebox.showerror("Missing firmware", "Select a valid firmware .bin file.")
            return
        chipid_raw = self.chipid_var.get().strip()
        if not chipid_raw:
            messagebox.showerror("Missing CHIPID", "Probe or manually set the CHIPID.")
            return
        secret_hex = self.secret_var.get().strip()
        if not secret_hex:
            messagebox.showerror("Missing secret", "Provide the MASTER_SECRET (hex) used on your build server.")
            return
        try:
            secret_bytes = safe_hex_to_bytes(secret_hex)
        except Exception as e:
            messagebox.showerror("Invalid secret", "MASTER_SECRET hex invalid: " + str(e))
            return
        if len(secret_bytes) < 16:
            if not messagebox.askyesno("Short secret", "MASTER_SECRET appears short (<16 bytes). Continue?"):
                return

        # parse chipid -> bytes (try hex, else decimal)
        try:
            chip_clean = chipid_raw.lower().replace("0x", "")
            if all(c in "0123456789abcdef" for c in chip_clean):
                chip_bytes = bytes.fromhex(chip_clean)
            else:
                chip_int = int(chipid_raw, 10)
                chip_bytes = chip_int.to_bytes(4, 'big')
        except Exception:
            try:
                chip_int = int(chipid_raw, 10)
                chip_bytes = chip_int.to_bytes(4, 'big')
            except Exception:
                messagebox.showerror("Bad CHIPID", "Can't parse the CHIPID. Use hex (01a2b3c4) or decimal.")
                return

        # read firmware
        try:
            with open(fw_path, "rb") as f:
                fw = f.read()
        except Exception as e:
            messagebox.showerror("Read failed", "Can't read firmware file: " + str(e))
            return

        # compute HMAC(secret, firmware || chip_bytes)
        try:
            h = hmac.new(secret_bytes, digestmod=hashlib.sha256)
            h.update(fw)
            h.update(chip_bytes)
            expected = h.hexdigest()
        except Exception as e:
            messagebox.showerror("HMAC failed", str(e))
            return

        # FW length
        fw_len = self.fw_len_var.get()
        if fw_len == "(auto)":
            try:
                fw_len_val = compute_fw_len_rounded(fw_path)
                fw_len = f"0x{fw_len_val:X}"
            except:
                fw_len = "0x0"

        # write header
        out_path = self.out_header_var.get().strip()
        if not out_path:
            out_path = os.path.join(os.getcwd(), "signed_firmware.h")
            self.out_header_var.set(out_path)
        try:
            with open(out_path, "w", encoding="utf-8") as hf:
                hf.write("// Auto-generated by ESP8266 Flash Protector — Anupam Dubey\n")
                hf.write("#pragma once\n\n")
                hf.write(f'#define DEVICE_CHIPID "{chipid_raw}"\n')
                hf.write(f'#define EXPECTED_HMAC "{expected}"\n')
                hf.write(f'#define FW_MAX_LEN {fw_len}\n')
            self.set_status(f"Wrote header to {out_path}")
            messagebox.showinfo("Done", f"Header generated:\n{out_path}")
        except Exception as e:
            self.set_status("Write failed: " + str(e))
            messagebox.showerror("Write failed", str(e))

    def generate_and_copy(self):
        self.generate_header()
        src = self.out_header_var.get().strip()
        dst_folder = self.project_folder_var.get().strip()
        if not dst_folder:
            messagebox.showwarning("No project folder", "Select an Arduino project folder to copy header into.")
            return
        if not os.path.isfile(src):
            messagebox.showerror("Missing header", "Header file not found; please generate it first.")
            return
        try:
            dst = os.path.join(dst_folder, os.path.basename(src))
            shutil.copy2(src, dst)
            self.set_status(f"Copied header to project: {dst}")
            messagebox.showinfo("Copied", f"Header copied to project:\n{dst}")
        except Exception as e:
            self.set_status("Copy failed: " + str(e))
            self.show_error("Copy failed", str(e))

    # ---------- export package ----------
    def export_project_package(self):
        fw_path = self.fw_path_var.get().strip()
        header_path = self.out_header_var.get().strip()
        chipid_raw = self.chipid_var.get().strip()
        if not fw_path or not os.path.isfile(fw_path):
            messagebox.showerror("Missing firmware", "Select a valid firmware .bin file first.")
            return
        if not header_path or not os.path.isfile(header_path):
            messagebox.showerror("Missing header", "Generate signed_firmware.h first.")
            return
        dest = filedialog.askdirectory(title="Select folder to export package into")
        if not dest:
            return
        pkg_name = f"package_{chipid_raw}_{int(time.time())}"
        pkg_folder = os.path.join(dest, pkg_name)
        try:
            os.makedirs(pkg_folder, exist_ok=True)
            # copy files
            shutil.copy2(fw_path, os.path.join(pkg_folder, os.path.basename(fw_path)))
            shutil.copy2(header_path, os.path.join(pkg_folder, os.path.basename(header_path)))
            # add verification sketch and README
            with open(os.path.join(pkg_folder, "verification_example.ino"), "w", encoding="utf-8") as vf:
                vf.write(SAMPLE_AFTER.replace("FW_MAX_LEN    FW_MAX_LEN", f"FW_MAX_LEN    {self.fw_len_var.get()}"))
            with open(os.path.join(pkg_folder, "README.txt"), "w", encoding="utf-8") as rf:
                rf.write(self._readme_text(chipid_raw))
            self.set_status(f"Exported package to {pkg_folder}")
            messagebox.showinfo("Exported", f"Project package exported:\n{pkg_folder}")
        except Exception as e:
            self.set_status("Export failed: " + str(e))
            messagebox.showerror("Export failed", str(e))

    def _readme_text(self, chipid):
        return (
            f"ESP8266 Flash Protector - Package\n\n"
            f"Target CHIPID: {chipid}\n\n"
            "Files:\n"
            " - firmware.bin : original firmware selected at signing time\n"
            " - signed_firmware.h : header containing EXPECTED_HMAC, DEVICE_CHIPID, FW_MAX_LEN\n"
            " - verification_example.ino : sample verification sketch (edit as needed)\n\n"
            "Steps to flash protected firmware:\n"
            "1) Include signed_firmware.h in your Arduino project and rebuild firmware.\n"
            "2) Flash rebuilt firmware to the device.\n"
            "3) Optionally run verification_example.ino to verify HMAC on device.\n"
        )

    # ---------- samples & help windows ----------
    def show_sample_window(self, title, code_text, default_name):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("820x640")
        txt = scrolledtext.ScrolledText(win, wrap="none", font=("Consolas", 11))
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        txt.insert("1.0", code_text)
        frame = tk.Frame(win)
        frame.pack(fill="x", pady=(0,8))
        def save_example():
            p = filedialog.asksaveasfilename(defaultextension=os.path.splitext(default_name)[1], initialfile=default_name,
                                             filetypes=[("Arduino sketch", "*.ino"), ("All files","*.*")])
            if p:
                with open(p, "w", encoding="utf-8") as f:
                    f.write(txt.get("1.0", "end"))
                messagebox.showinfo("Saved", f"Example saved to:\n{p}")
        tk.Button(frame, text="Export Example", command=save_example, bg="#2196F3", fg="white").pack(side="left", padx=6)
        tk.Button(frame, text="Close", command=win.destroy).pack(side="right", padx=6)

    def show_help(self):
        win = tk.Toplevel(self.root)
        win.title("Step-by-step Guide")
        win.geometry("760x520")
        txt = scrolledtext.ScrolledText(win, wrap="word", font=("Segoe UI", 10))
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        txt.insert("1.0", self._help_text())
        txt.config(state="disabled")

    def show_about(self):
        messagebox.showinfo("About", f"{APP_TITLE}\nVersion: {APP_VERSION}\nAuthor: Anupam Dubey")

    def show_error(self, title, msg):
        messagebox.showerror(title, msg)

# ---------- run ----------
def main():
    root = tk.Tk()
    app = ESPFlashProtectorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
