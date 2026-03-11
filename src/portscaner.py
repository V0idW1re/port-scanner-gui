# ==============================================================
# portscan.py
# Εφαρμογή Port Scanner με γραφικό περιβάλλον (GUI) σε Python
# Συγγραφέας: Ιωάννης Κακασάς
# Περιγραφή: Σαρώνει θύρες TCP, εμφανίζει αποτελέσματα στο GUI
# και επιτρέπει αποθήκευση αποτελεσμάτων σε αρχείο.
# ==============================================================

import os
import socket
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from tkinter import *

# --------------------------------------------------------------
# 1. ΡΥΘΜΙΣΕΙΣ ΚΑΙ ΚΑΘΟΛΙΚΕΣ ΜΕΤΑΒΛΗΤΕΣ
# --------------------------------------------------------------

# Φάκελος αποθήκευσης αποτελεσμάτων (για Android / PyDroid)
SAVE_DIR = "/storage/emulated/0/Documents/Python/"
os.makedirs(SAVE_DIR, exist_ok=True)  # Δημιουργία φακέλου αν δεν υπάρχει

DEFAULT_TIMEOUT = 2.0       # Μέγιστος χρόνος αναμονής για κάθε θύρα (δευτερόλεπτα)
MAX_WORKERS = 100           # Μέγιστος αριθμός νημάτων (threads) που θα τρέχουν ταυτόχρονα

# Λίστες για αποθήκευση αποτελεσμάτων και καταγραφών
log = []                    # Αναλυτικό log των μηνυμάτων
ports_found = []            # Λίστα με τις ανοιχτές θύρες που βρέθηκαν
result_queue = Queue()      # Ουρά επικοινωνίας GUI ↔ εργαζομένων (thread-safe)

# Μεταβλητές για εμφάνιση κατάστασης στο GUI
current_start = 1
current_end = 1024
current_target_display = 'localhost'

# --------------------------------------------------------------
# 2. ΚΥΡΙΑ ΛΟΓΙΚΗ ΣΑΡΩΣΗΣ ΘΥΡΩΝ
# --------------------------------------------------------------

def scanPort(target_ip, port):
    """
    Ελέγχει αν μια συγκεκριμένη θύρα (port) είναι ανοικτή.
    Αν η σύνδεση είναι επιτυχής, αποθηκεύει το αποτέλεσμα στην ουρά.
    """
    try:
        # Δημιουργία TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(DEFAULT_TIMEOUT)  # Ορισμός timeout για αποφυγή καθυστερήσεων

        # Προσπάθεια σύνδεσης στη θύρα
        code = s.connect_ex((target_ip, port))  # 0 = επιτυχής σύνδεση
        if code == 0:
            msg = f' Port {port}\t[open]'
            result_queue.put(('open', port, msg))  # Επιστροφή θετικού αποτελέσματος στην ουρά
        s.close()

    except OSError as e:
        # Συνήθη σφάλματα: πάρα πολλά sockets ή προβλήματα δικτύου
        result_queue.put(('error', port, f'> OSError on port {port}: {e}'))
    except Exception as e:
        result_queue.put(('error', port, f'> Exception on port {port}: {e}'))

def scan_worker(target_str, start_port, end_port):
    """
    Εκτελεί τη σάρωση σε background thread.
    Χρησιμοποιεί ThreadPoolExecutor για να περιορίσει τον αριθμό των ταυτόχρονων νημάτων.
    """
    global current_target_display
    try:
        # Μετατροπή domain/IP σε IP address
        target_ip = socket.gethostbyname(target_str)
    except Exception as e:
        result_queue.put(('error', 0, f"> Could not resolve target '{target_str}': {e}"))
        return

    current_target_display = target_ip
    total = end_port - start_port + 1
    result_queue.put(('info', 0, f"> Scanning {target_str} ({target_ip}) ports {start_port}-{end_port} (total {total})"))

    # Δημιουργία pool από threads για σάρωση
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        futures = []
        for p in range(start_port, end_port + 1):
            # Δημιουργία νέας εργασίας για κάθε θύρα
            futures.append(exe.submit(scanPort, target_ip, p))

        # Αναμονή να ολοκληρωθούν όλα τα threads
        for fut in futures:
            try:
                fut.result()  # Ανακτά σφάλματα από κάθε thread αν υπάρχουν
            except Exception:
                pass

    result_queue.put(('info', 0, "> Scan finished."))

# --------------------------------------------------------------
# 3. ΕΝΗΜΕΡΩΣΗ ΤΟΥ GUI ΜΕ ΑΠΟΤΕΛΕΣΜΑΤΑ
# --------------------------------------------------------------

def poll_results():
    """
    Εκτελείται περιοδικά (κάθε 150 ms) από το GUI.
    Διαβάζει αποτελέσματα από την ουρά (result_queue)
    και ενημερώνει με ασφάλεια το γραφικό περιβάλλον.
    """
    updated = False
    try:
        while True:
            typ, port, msg = result_queue.get_nowait()
            if typ == 'open':
                ports_found.append(port)
                log.append(msg)
                listbox.insert('end', msg)
            elif typ in ('error', 'info'):
                log.append(msg)
                listbox.insert('end', msg)
            updated = True
    except Exception:
        # Αν η ουρά είναι άδεια (queue.Empty), απλώς συνεχίζει
        pass

    if updated:
        updateResult()
    # Προγραμματίζει την επόμενη εκτέλεση αυτής της συνάρτησης
    gui.after(150, poll_results)

def updateResult():
    """
    Ενημερώνει το label στο GUI με τον αριθμό των ανοιχτών θυρών.
    """
    total = (current_end - current_start + 1) if current_end >= current_start else 0
    rtext = f" [ {len(ports_found)} / {total} ] ~ {current_target_display}"
    L27.configure(text=rtext)

# --------------------------------------------------------------
# 4. ΣΥΝΑΡΤΗΣΕΙΣ ΚΟΥΜΠΙΩΝ GUI
# --------------------------------------------------------------

def startScan():
    """
    Εκτελείται όταν πατηθεί το κουμπί "Start Scan".
    Διαβάζει τις τιμές από τα πεδία του GUI και ξεκινά τη σάρωση.
    """
    global log, ports_found, current_start, current_end, current_target_display

    clearScan()
    log = []
    ports_found = []

    # Έλεγχος εγκυρότητας θυρών
    try:
        s_port = int(L24.get())
        e_port = int(L25.get())
    except ValueError:
        listbox.insert('end', "> Error: start and end ports must be integers.")
        return

    if s_port < 1 or e_port < 1 or s_port > 65535 or e_port > 65535:
        listbox.insert('end', "> Error: ports must be in range 1-65535.")
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

    # Δημιουργία και εκκίνηση νέου thread για τη σάρωση
    th = threading.Thread(target=scan_worker, args=(target_input, s_port, e_port), daemon=True)
    th.start()

def saveScan():
    """
    Αποθηκεύει τα αποτελέσματα της σάρωσης σε αρχείο .txt
    στον προκαθορισμένο φάκελο SAVE_DIR.
    """
    if not log:
        listbox.insert('end', "> No scan results to save.")
        return

    # Δημιουργία ονόματος αρχείου βασισμένο στον στόχο
    safe_target = str(current_target_display).replace('/', '_').replace(':', '_')
    filename = f"portscan-{safe_target}.txt"
    full_path = os.path.join(SAVE_DIR, filename)

    try:
        with open(full_path, "w", encoding="utf-8") as f:
            header = [
                "> Port Scanner Results",
                "=" * 24,
                f" Target: {L22.get().strip()}",
                f" Resolved IP: {current_target_display}",
                f" Ports: {current_start}-{current_end}",
                ""
            ]
            f.write("\n".join(header + log))
        listbox.insert('end', f"> Results saved to:\n{full_path}")
    except Exception as e:
        listbox.insert('end', f"> Error saving file: {e}")

def clearScan():
    """Καθαρίζει τη λίστα αποτελεσμάτων στο GUI."""
    listbox.delete(0, 'end')

# --------------------------------------------------------------
# 5. ΔΗΜΙΟΥΡΓΙΑ ΤΟΥ ΓΡΑΦΙΚΟΥ ΠΕΡΙΒΑΛΛΟΝΤΟΣ (Tkinter)
# --------------------------------------------------------------

gui = Tk()
gui.title('Port Scanner GUI')
gui.geometry("420x620+20+20")  # Μέγεθος παραθύρου (ταιριάζει και σε Android)

# Χρωματική παλέτα (ενδέχεται να μην υποστηρίζεται παντού)
try:
    gui.tk_setPalette(background='#222222', foreground='#00ee00',
                      activeBackground='#111111', activeForeground='#00ff00')
except Exception:
    pass

# Τίτλος εφαρμογής
L11 = Label(gui, text="Port Scanner", font=("Helvetica", 18, 'underline'))
L11.pack(pady=8)

# Πεδίο εισαγωγής διεύθυνσης στόχου (IP ή domain)
frm_target = Frame(gui)
frm_target.pack(pady=4, fill='x', padx=12)
Label(frm_target, text="Target:").pack(side='left')
L22 = Entry(frm_target)
L22.pack(side='left', fill='x', expand=True, padx=8)
L22.insert(0, "localhost")

# Πεδίο εισαγωγής εύρους θυρών (αρχή και τέλος)
frm_ports = Frame(gui)
frm_ports.pack(pady=4, fill='x', padx=12)
Label(frm_ports, text="Start Port:").pack(side='left')
L24 = Entry(frm_ports, width=8)
L24.pack(side='left', padx=6)
L24.insert(0, "1")
Label(frm_ports, text="End Port:").pack(side='left', padx=(10, 0))
L25 = Entry(frm_ports, width=8)
L25.pack(side='left', padx=6)
L25.insert(0, "1024")

# Ετικέτα εμφάνισης προόδου (π.χ. [ 5 / 1024 ])
frm_res = Frame(gui)
frm_res.pack(pady=6, fill='x', padx=12)
Label(frm_res, text="Results:").pack(side='left')
L27 = Label(frm_res, text="[ ... ]")
L27.pack(side='left', padx=8)

# Πλαίσιο εμφάνισης αποτελεσμάτων (Listbox + scrollbar)
frame = Frame(gui)
frame.pack(padx=12, pady=6, fill='both', expand=True)
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
listbox = Listbox(frame, width=60, height=15, yscrollcommand=scrollbar.set)
listbox.pack(side=LEFT, fill='both', expand=True)
scrollbar.config(command=listbox.yview)

# Κουμπιά ενεργειών
frm_btn = Frame(gui)
frm_btn.pack(pady=8)
B11 = Button(frm_btn, text="Start Scan", command=startScan, width=15)
B11.pack(side='left', padx=6)
B21 = Button(frm_btn, text="Save Result", command=saveScan, width=15)
B21.pack(side='left', padx=6)
B31 = Button(frm_btn, text="Clear", command=clearScan, width=15)
B31.pack(side='left', padx=6)

# --------------------------------------------------------------
# 6. ΕΝΑΡΞΗ ΒΡΟΧΟΥ ΕΝΗΜΕΡΩΣΗΣ ΚΑΙ ΕΚΚΙΝΗΣΗ GUI
# --------------------------------------------------------------

# Εκκινεί την περιοδική ανάγνωση της ουράς αποτελεσμάτων
gui.after(150, poll_results)

# Ενεργοποιεί το κυρίως loop του Tkinter
gui.mainloop()
