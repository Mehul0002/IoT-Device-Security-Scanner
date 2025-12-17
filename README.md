# 🔐 IoT Device Security Scanner (GUI-Based)

A **Python-based GUI application** that scans IoT devices on a local network and identifies common security vulnerabilities. This tool leverages **Nmap** for network scanning and **MQTT** security checks to help users understand and improve IoT security in a safe and ethical way.

---

## 📌 Project Overview

With the rapid growth of Internet of Things (IoT) devices, security has become a major concern. Many IoT devices run with **default configurations**, **weak credentials**, or **open services**, making them vulnerable to attacks.

This project provides a **desktop GUI application** that:

* Discovers IoT devices on a local network
* Performs basic security checks
* Displays results in a user-friendly, color-coded interface

The project is designed for **students, beginners, and cybersecurity learners**.

---

## 🚀 Features

* 🔍 **Network Device Discovery**

  * Scan local network ranges (e.g., `192.168.1.0/24`)
  * Identify connected IoT devices

* 🔐 **Security Checks**

  * Outdated firmware detection *(simulated)*
  * Weak or default password detection *(non-intrusive)*
  * Open and risky port scanning using Nmap
  * Vulnerable service identification (FTP, Telnet, etc.)
  * Default configuration checks

* 📡 **MQTT Security Analysis**

  * Detect anonymous MQTT access
  * Check default MQTT topics
  * Identify insecure MQTT configurations

* 🖥️ **Graphical User Interface (GUI)**

  * Simple and intuitive interface
  * Scan button with progress indicator
  * Results displayed in a table
  * Color-coded risk levels:

    * 🟢 Safe
    * 🟡 Warning
    * 🔴 Critical

---

## 🛠️ Technologies Used

* **Python 3**
* **Nmap** (via `python-nmap`)
* **MQTT** (`paho-mqtt`)
* **GUI Framework**: Tkinter / PyQt5

---

## 📂 Project Structure

```
IoT-Device-Security-Scanner/
│
├── main.py              # GUI logic and application entry point
├── scanner.py           # Network and port scanning logic
├── mqtt_checker.py      # MQTT security checks
├── utils.py             # Helper functions
├── requirements.txt     # Project dependencies
└── README.md            # Project documentation
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/your-username/IoT-Device-Security-Scanner.git
cd IoT-Device-Security-Scanner
```

### 2️⃣ Install Dependencies

Make sure **Python 3** is installed.

```bash
pip install -r requirements.txt
```

> ⚠️ **Nmap must be installed separately**

* Windows: Download from [https://nmap.org/download.html](https://nmap.org/download.html)
* Linux:

```bash
sudo apt install nmap
```

---

## ▶️ How to Run

```bash
python main.py
```

The GUI window will open. Enter your local network range and click **Scan Network**.

---

## 🧠 Example Use Cases

* Cybersecurity learning and practice
* College mini-project or final-year project
* Understanding IoT vulnerabilities
* Defensive security demonstrations

---

## 🔒 Security & Ethics Notice

* This tool scans **only local networks**
* Do **NOT** use on networks you do not own or have permission to test
* No brute-force or exploitation techniques are used
* Firmware and password checks are **simulated** for safety

---

## ⚠️ Disclaimer

This project is intended **strictly for educational and ethical purposes**. The author is not responsible for any misuse of this software.

---

## 🤝 Contributing

Contributions, suggestions, and improvements are welcome!

1. Fork the repository
2. Create a new branch
3. Commit your changes
4. Open a Pull Request

---

## 📜 License

This project is licensed under the **MIT License**. You are free to use, modify, and distribute it for educational purposes.

---

## ⭐ Support

If you find this project helpful, consider giving it a ⭐ on GitHub!

---

**Developed for learning and defensive cybersecurity research.**
