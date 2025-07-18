# 🔍 NetScanX

**NetScanX** is an advanced Python-based network utility tool designed for ethical hackers, cybersecurity learners, and network admins.  
It offers multiple powerful features like local network scanning, IP geolocation, MAC vendor lookup, port scanning, and more — all from one terminal UI.

![NetScanX Output](img/netscan_banner.png)

## 🚀 Features

- 📱 Local Network IP & MAC Scanner  
- 🍿 MAC Vendor Lookup  
- 🌍 Public IP Location + ASN Info  
- 🔎 VPN/Proxy/Tor Detection  
- 🔓 Open Port Scanner (Common Ports)  
- 🌐 Hostname Resolver  
- 🧠 IP Type & Range Analyzer  

## 🖥️ Supported Platforms

- ✅ Windows  
- ✅ Linux  

## 📦 Installation

### ⚙️ 1. Clone the repository:

```bash
git clone https://github.com/Rorychhattish/NetscanX.git
cd NetscanX
🧰 Requirements
Make sure Python is installed.

Install the dependencies via:
pip install -r requirements.txt

▶️ **How to Run NetScanX**
🪟 **On Windows**:
Open Command Prompt or PowerShell.
Navigate to the cloned folder:

cd NetscanX
python NetscanX.py
⚠️ Run as Administrator if MAC scanning fails or no devices are detected.

🐧 **On Linux (Ubuntu, Kali, etc.)**:
Open Terminal
Navigate to the cloned folder:
cd NetscanX
sudo python3 NetscanX.py
⚠️ If you face PermissionError or no output on scanning, make sure you're using sudo.

🌐 How to Run NetScanX Globally on Linux
If you want to run NetScanX from any directory in the terminal (without navigating to the folder every time), follow these steps:

✅ Step 1: Make the script executable
chmod +x NetscanX.py

✅ Step 2: Create a symbolic link to a global location (like /usr/local/bin)
sudo ln -s $(pwd)/NetscanX.py /usr/local/bin/netscanx
🔹 Now you can run the tool globally from any terminal using:

sudo netscanx
⚠️ Note: sudo is required because the tool uses ARP scanning and raw sockets.

👨‍💻 **Powered by Chhattish**
This tool was created by Chhattish, a student passionate about cybersecurity, network programming, and ethical hacking.
Feel free to ⭐ star this repo if you like it!

