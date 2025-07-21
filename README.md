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

📦 **NetScanX Installation & Usage Guide**
⚙️**1. Clone the Repository**
      git clone https://github.com/Rorychhattish/NetscanX.git
      cd NetscanX
🧰 **2. Set Up Python Virtual Environment (Recommended)**
      python3 -m venv venv
      source venv/bin/activate
    ✅ This keeps dependencies isolated and avoids system-wide conflicts.

📦 **3. Install Required Dependencies**
      pip install -r requirements.txt
      
▶️ **4. Run NetScanX**
      sudo python3 NetscanX.py
  ⚠️ sudo is required to perform low-level network operations like ARP scanning.
  If not run with sudo, you may get Permission Error or no devices detected.


**🌐 Run NetScanX Globally (Optional)**
      If you want to use netscanx as a command from any directory, follow these steps:

  ✅ **Step 1: Make the script executable**
      chmod +x NetscanX.py

  ✅ **Step 2: Create a global symbolic link**
      sudo ln -s $(pwd)/NetscanX.py /usr/local/bin/netscanx

  🔹 **Now you can run it globally:**
      sudo netscanx
    🔁 You still need to activate the virtual environment first if you used venv. You can automate this in future with a wrapper script if you want.


🧠 **Pro Tip: Auto-activate venv on global run (optional advanced)**
      If you want to make global command use the virtual environment automatically, create a wrapper script:

      netscanx.sh:
        #!/bin/bash
        cd /path/to/NetscanX
        source venv/bin/activate
        sudo python3 NetscanX.py
        
      Then symlink this script:  
        chmod +x netscanx.sh
        sudo ln -s $(pwd)/netscanx.sh /usr/local/bin/netscanx
      # Now netscanx will activate venv and run the tool in one go.

👨‍💻 **Powered by Chhattish**
This tool was created by Chhattish, a student passionate about cybersecurity, network programming, and ethical hacking.
Feel free to ⭐ star this repo if you like it!
