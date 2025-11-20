# Port Scanner GUI (Python + Tkinter)

A simple, lightweight, and fully GUI-powered port scanner written in Python.  
Designed to work on desktop **and** Android (via Pydroid), this tool allows you to scan a range of ports on any target and saves results to a text file.

---

## Features

 **Graphical User Interface** (Tkinter)
- **Multithreaded port scanning** using `ThreadPoolExecutor`
- Resolve hostname → IP automatically
- Save scan results to file
- Real-time scrollable output
- Shows open ports count and progress
- Mobile-friendly UI (works great in Pydroid)

---

## Project Structure

port-scanner-gui/
│
├── src/
│ └── portscanner.py
│
├── README.md
├── LICENSE
└── .gitignore

---

## Usage

### **Run the scanner**

python src/portscanner.py

Choose a target
Examples:
localhost
192.168.1.1
scanme.nmap.org
Choose port range

Choose port range
Default: 1 - 1024

Click “Start Scan”
The GUI will:
show open ports,
display errors,
allow save results.

## Requirements
Python 3.8+
Tkinter (usually included with Python)
Works on Android (Pydroid 3)
Optional installation: pip install tk

## License
This project is licensed under the MIT License (see LICENSE file).

## Contributing
Pull requests are welcome!
If you'd like new features added (e.g., UDP scanning, banner grabbing, themes), feel free to open an issue.

## Support
If this project helped you, consider giving it a ⭐ on GitHub!
