# -------------------------
# Port Scanner with GUI
# -------------------------

import os
import socket
import threading
import time
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from tkinter import *

# -------------------------
# Configuration / Globals
# -------------------------
# Directory where scan results will be saved
SAVE_DIR = "/storage/emulated/0/Documents/Python/"
os.makedirs(SAVE_DIR, exist_ok=True)

# Timeout for socket connections
DEFAULT_TIMEOUT = 2.0
# Max concurrent scanning threads
MAX_WORKERS = 100

# Lists to store log messages and open ports
log = []
ports_found = []
# Thread-safe queue for sending results back to the GUI
result_queue = Queue()

# Variables to track current scan details
current_start = 1
current_end = 1024
current_target_display = 'localhost'

# -------------------------
# Scanning code
# -------------------------
def scanPort(target_ip, port):
    """
    Attempt to connect to a single port.
    If open, push result to the result_queue.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(DEFAULT_TIMEOUT)
        code = s.connect_ex((target_ip, port))

        if code == 0:  # Port is open
            msg = f' Port {port} \t[open]'
            result_queue.put(('open', port, msg))
        s.close()

    except OSError as e:
        # Possible when too many sockets or network issues
        result_queue.put(('error', port, f'> OSError on port {port}: {e}'))
    except Exception as e:
        result_queue.put(('error', port, f'> Exception on port {port}: {e}'))


def scan_worker(target_str, start_port, end_port):
    """
    Background worker function that launches multiple scanPort tasks.
    Runs in a separate thread so GUI stays responsive.
    """
    global current_target_display

    # Resolve hostname to IP
    try:
        target_ip = socket.gethostbyname(target_str)
    except Exception as e:
        result_queue.put(('error', 0, f"> Could not resolve target '{target_str}': {e}"))
        return

    current_target_display = target_ip
    total = end_port - start_port + 1
    result_queue.put(('info', 0, f"> Scanning {target_str} ({target_ip}) ports {start_port}-{end_port} (total {total})"))

    # Use ThreadPoolExecutor to limit concurrency
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        futures = []
        for p in range(start_port, end_port + 1):
            futures.append(exe.submit(scanPort, target_ip, p))

        # Wait for all port checks to finish
        for fut in futures:
            try:
                fut.result()
            except Exception:
                pass

    result_queue.put(('info', 0, f"> Scan finished."))


# -------------------------
# GUI-safe polling / updates
# -------------------------
def poll_results():
    """
    Runs on the main GUI thread.
    Retrieves messages from the result queue and updates the Listbox.
    """
    updated = False
    try:
        while True:
            typ, port, msg = result_queue.get_nowait()
            # Add all messages to the log and listbox
            log.append(msg)
            listbox.insert('end', msg)

            if typ == 'open':
                ports_found.append(port)  # Keep track of open ports

            updated = True
    except Exception:
        pass

    # Update label showing scan progress
    if updated:
        updateResult()

    # Schedule next poll
    gui.after(150, poll_results)


def updateResult():
    """
    Update the small status label showing: [open ports / total] ~ target
    """
    total = (current_end - current_start + 1) if current_end >= current_start else 0
    rtext = f" [ {len(ports_found)} / {total} ] ~ {current_target_display}"
    L27.configure(text=rtext)


# -------------------------
# Button callbacks
# -------------------------
def startScan():
    """
    Triggered when Start Scan button is pressed.
    Reads user input, validates it, and starts scanning thread.
    """
    global log, ports_found, current_start, current_end, current_target_display

    clearScan()
    log = []
    ports_found = []

    # Read port range inputs
    try:
        s_port = int(L24.get())
        e_port = int(L25.get())
    except ValueError:
        listbox.insert('end', "> Error: start and end ports must be integers.")
        return

    # Validate port values
    if s_port < 1 or e_port < 1 or s_port > 65535 or e_port > 65535:
        listbox.insert('end', "> Error: ports must be in 1-65535.")
        return
    if s_port > e_port:
        listbox.insert('end', "> Error: start port must be <= end port.")
        return

    current_start = s_port
    current_end = e_port

    target_input = L22.get().strip()
    if not target_input:
        listbox.insert('end', "> Error: target cannot be empty.")
        return

    # Launch background thread for scanning
    th = threading.Thread(target=scan_worker, args=(target_input, s_port, e_port), daemon=True)
    th.start()


def saveScan():
    """
    Saves the log of results to a text file.
    """
    if not log:
        listbox.insert('end', "> No scan results to save.")
        return

    # Sanitize filename
    safe_target = str(current_target_display).replace('/', '_').replace(':', '_')
    filename = f"portscan-{safe_target}.txt"
    full_path = os.path.join(SAVE_DIR, filename)

    try:
        with open(full_path, "w", encoding="utf-8") as f:
            header = [
                "> Port Scanner",
                "=" * 14,
                f" Target: {L22.get().strip()}",
                f" Resolved IP: {current_target_display}",
                f" Ports: {current_start} / {current_end}",
                ""
            ]
            f.write("\n".join(header + log))
        listbox.insert('end', f"> Results saved to:\n{full_path}")
    except Exception as e:
        listbox.insert('end', f"> Error saving file: {e}")


def clearScan():
    """Clear the Listbox display."""
    listbox.delete(0, 'end')


# -------------------------
# Build GUI
# -------------------------
gui = Tk()
gui.title('Port Scanner')
# Compact size suitable for mobile
gui.geometry("420x620+20+20")

# Try to set color theme
try:
    gui.tk_setPalette(background='#222222', foreground='#00ee00', activeBackground='#111111', activeForeground='#222222')
except Exception:
    pass

# Header label
L11 = Label(gui, text="Port Scanner", font=("Helvetica", 18, 'underline'))
L11.pack(pady=8)

# Target input
frm_target = Frame(gui)
frm_target.pack(pady=4, fill='x', padx=12)
Label(frm_target, text="Target:").pack(side='left')
L22 = Entry(frm_target)
L22.pack(side='left', fill='x', expand=True, padx=8)
L22.insert(0, "localhost")

# Port range inputs
frm_ports = Frame(gui)
frm_ports.pack(pady=4, fill='x', padx=12)
Label(frm_ports, text="Start Port:").pack(side='left')
L24 = Entry(frm_ports, width=8)
L24.pack(side='left', padx=6)
L24.insert(0, "1")
Label(frm_ports, text="End Port:").pack(side='left', padx=(10,0))
L25 = Entry(frm_ports, width=8)
L25.pack(side='left', padx=6)
L25.insert(0, "1024")

# Results label
frm_res = Frame(gui)
frm_res.pack(pady=6, fill='x', padx=12)
Label(frm_res, text="Results:").pack(side='left')
L27 = Label(frm_res, text="[ ... ]")
L27.pack(side='left', padx=8)

# Listbox with scrollbar
frame = Frame(gui)
frame.pack(padx=12, pady=6, fill='both', expand=True)
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
listbox = Listbox(frame, width=60, height=15, yscrollcommand=scrollbar.set)
listbox.pack(side=LEFT, fill='both', expand=True)
scrollbar.config(command=listbox.yview)

# Buttons
frm_btn = Frame(gui)
frm_btn.pack(pady=8)
B11 = Button(frm_btn, text="Start Scan", command=startScan, width=15)
B11.pack(side='left', padx=6)
B21 = Button(frm_btn, text="Save Result", command=saveScan, width=15)
B21.pack(side='left', padx=6)
B31 = Button(frm_btn, text="Clear", command=clearScan, width=15)
B31.pack(side='left', padx=6)

# Start periodic queue polling
gui.after(150, poll_results)

# Run GUI event loop
gui.mainloop()
