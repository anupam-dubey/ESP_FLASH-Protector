import tkinter as tk
from tkinter import ttk, messagebox
import serial
import serial.tools.list_ports

BAUD = 115200
CH_LEN = 64


def rol(v, r):
    return ((v << r) | (v >> (8 - r))) & 0xFF


class ESPProtectorApp:

    def __init__(self, root):
        self.root = root
        self.root.title("ESP8266 Flash Protector — Anupam Dubey")
        self.root.geometry("900x650")

        self.ser = None
        self.challenge = None

        self.build_ui()
        self.refresh_ports()

        self.root.after(100, self.poll_serial)

    # -------------------------------------------------
    def build_ui(self):

        top = tk.Frame(self.root)
        top.pack(fill="x", padx=10, pady=5)

        tk.Label(top, text="COM Port:").pack(side="left")
        self.port_box = ttk.Combobox(top, width=15, state="readonly")
        self.port_box.pack(side="left", padx=5)

        ttk.Button(top, text="Refresh", command=self.refresh_ports).pack(side="left", padx=5)
        ttk.Button(top, text="Connect", command=self.connect).pack(side="left", padx=5)
        ttk.Button(top, text="Disconnect", command=self.disconnect).pack(side="left", padx=5)
        ttk.Button(top, text="Authorize", command=self.authorize).pack(side="left", padx=10)

        # Challenge box
        tk.Label(self.root, text="Authorization Challenge (64 bytes)").pack(anchor="w", padx=10)
        self.challenge_box = tk.Text(self.root, height=4, font=("Consolas", 11))
        self.challenge_box.pack(fill="x", padx=10, pady=5)
        self.challenge_box.config(state="disabled")

        # Log box
        tk.Label(self.root, text="Serial Event Log").pack(anchor="w", padx=10)
        self.log_box = tk.Text(self.root, height=22, font=("Consolas", 10))
        self.log_box.pack(fill="both", expand=True, padx=10, pady=5)

        # Status bar
        self.status = tk.StringVar()
        self.status.set("Status: Idle")
        tk.Label(self.root, textvariable=self.status,
                 relief="sunken", anchor="w").pack(fill="x", side="bottom")

    # -------------------------------------------------
    def log(self, msg):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

    # -------------------------------------------------
    def set_status(self, msg):
        self.status.set("Status: " + msg)

    # -------------------------------------------------
    def refresh_ports(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_box["values"] = ports
        if ports:
            self.port_box.current(0)

    # -------------------------------------------------
    def connect(self):
        try:
            port = self.port_box.get()
            self.ser = serial.Serial(port, BAUD, timeout=0)
            self.log(f"INFO: Connected to {port}")
            self.set_status("Connected — reset ESP")
        except Exception as e:
            messagebox.showerror("Serial Error", str(e))

    # -------------------------------------------------
    def disconnect(self):
        if self.ser:
            self.ser.close()
            self.ser = None
            self.log("INFO: Disconnected")
            self.set_status("Disconnected")

    # -------------------------------------------------
    def poll_serial(self):
        if self.ser and self.ser.in_waiting:
            try:
                raw = self.ser.readline().decode(errors="ignore").strip()
                if raw:
                    self.log("ESP: " + raw)
                    self.handle_line(raw)
            except:
                pass

        self.root.after(60, self.poll_serial)

    # -------------------------------------------------
    def handle_line(self, line):
        if "CHALLENGE:" in line:
            part = line.split("CHALLENGE:")[1]

            hexdata = "".join(c for c in part if c in "0123456789abcdefABCDEF")

            if len(hexdata) >= CH_LEN * 2:
                hexdata = hexdata[:CH_LEN * 2]
                self.challenge = bytes.fromhex(hexdata)

                self.challenge_box.config(state="normal")
                self.challenge_box.delete("1.0", "end")
                self.challenge_box.insert("end", hexdata)
                self.challenge_box.config(state="disabled")

                self.set_status("Challenge received")

    # -------------------------------------------------
    def authorize(self):
        if not self.challenge:
            messagebox.showwarning("No challenge", "Challenge not received yet.")
            return

        resp = bytearray(CH_LEN)

        for i in range(CH_LEN):
            r = self.challenge[i]
            r ^= (i * 37) & 0xFF
            r = rol(r, (i % 5) + 1)
            r ^= (self.challenge[(i + 11) % CH_LEN] >> 1)
            resp[i] = r

        self.ser.write(resp.hex().encode() + b"\n")

        self.log("INFO: Authorization response sent")
        self.set_status("Authorization sent")

# -----------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = ESPProtectorApp(root)
    root.mainloop()
