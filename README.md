# 🛡️ CyberSecurity Network Security Tool

This Python-based network security tool features a graphical user interface (GUI) built using the `tkinter` library. The tool detects **promiscuous mode** and **ARP poisoning** in a network, with a sleek dark theme and cybersecurity-related icons. It aims to assist beginners and professionals alike in identifying network vulnerabilities.

## 🚀 Features

- **Promiscuous Mode Detection**: Identifies if any network interface is in promiscuous mode.
- **ARP Poisoning Detection**: Detects ARP spoofing attacks within the network.
- **User-Friendly GUI**: Dark-themed interface with cybersecurity-styled icons for easy navigation.

## 📋 Requirements

- **Python 3.x**
- Required Python libraries:
  - `tkinter`
  - `psutil`
  - `scapy`
  - `Pillow`

### 🔧 Installation

To install the required libraries, run the following command:

```bash
pip install psutil scapy Pillow
```

## 🚀 How to Run

To run the tool, use the following command:

```bash
python project.py
```

## 📝 Code Overview

### Main Interface

The main interface is built with `tkinter`, providing buttons that open windows for:

- **Promiscuous Mode Detection**: Allows you to enter an IP address to check if any network device is operating in promiscuous mode.
- **ARP Poisoning Detection**: Allows you to select a network interface to detect and monitor ARP spoofing attacks in real-time.

### Functions

- `get_mac(ip)`: Returns the MAC address associated with a given IP address.
- `process(packet)`: Processes network packets to detect ARP spoofing.
- `sniffs(e)`: Sniffs network packets to identify ARP poisoning attacks.
- `promiscs(e1)`: Checks if a device on the network is operating in promiscuous mode.
- `get_macs(ip)`: Sends a packet to detect devices operating in promiscuous mode.


## 🤝 Acknowledgements

- [scapy](https://github.com/secdev/scapy): For enabling packet manipulation and crafting.
- [Pillow](https://python-pillow.org/): For handling image manipulation within the GUI.
- The cybersecurity community for continued inspiration and knowledge-sharing.

## 🛠️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

### 📝 Notes

You can include screenshots in the "Screenshots" section and ensure the **LICENSE** file is added if you want to distribute it under MIT or another license type.
