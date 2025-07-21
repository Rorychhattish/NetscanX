from scapy.all import ARP, Ether, srp
import requests
from mac_vendor_lookup import MacLookup
import os
import ipaddress
import socket

# 🎨 Clear Terminal
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

# 🔍 Get MAC Vendor Name
def get_mac_vendor(mac):
    try:
        return MacLookup().lookup(mac)
    except:
        return "Unknown Vendor"

# 🌍 Get Geo Location & ASN Info + VPN/Proxy Detection
def get_location_from_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()

        print("\n🌍 IP LOCATION & ASN INFO")
        print("────────────────────────────────")
        print(f"🆔 IP Address   : {data.get('ip')}")
        print(f"🏙️ City         : {data.get('city')}")
        print(f"📍 Region       : {data.get('region')}")
        print(f"🌎 Country      : {data.get('country')}")
        print(f"🌭 Coordinates  : {data.get('loc')}")
        print(f"🕒 Timezone     : {data.get('timezone')}")

        org = data.get('org', '')
        if org.startswith("AS"):
            asn, as_name = org.split(' ', 1)
            print(f"🆔 ASN Number   : {asn}")
            print(f"🏢 ASN Provider : {as_name}")
        else:
            print(f"🏢 Organization : {org}")

        latlong = data.get("loc")
        if latlong:
            print(f"🗌 Google Maps  : https://www.google.com/maps?q={latlong}")

        privacy = data.get("privacy", {})
        if privacy.get("vpn") or privacy.get("proxy") or privacy.get("tor"):
            print("🛡️ VPN/Proxy/Tor: Likely in use")
        else:
            print("🛡️ VPN/Proxy/Tor: Not detected")

    except Exception as e:
        print(f"[!] Error: {e}")

# 📱 Scan Local Network
def scan(ip_range):
    print(f"\n📡 Scanning Local Network Range: {ip_range}")
    print("────────────────────────────────────────────")

    # Prepare ARP request
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send packet and receive responses
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []

    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        vendor = get_mac_vendor(mac)

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = "Unknown"

        devices.append({
            'ip': ip,
            'mac': mac,
            'vendor': vendor,
            'hostname': hostname
        })

    print(f"\n📋 Connected Devices Found: {len(devices)}")
    print("────────────────────────────────────────────")

    for idx, device in enumerate(devices, 1):
        print(f"\n#{idx}")
        print(f"📱 IP Address  : {device['ip']}")
        print(f"🔗 MAC Address : {device['mac']}")
        print(f"🍿 Vendor      : {device['vendor']}")
        print(f"🖥️ Hostname    : {device['hostname']}")

        # Location lookup only for public IPs
        if not device['ip'].startswith(("192.168", "10.", "172.")):
            get_location_from_ip(device['ip'])
        else:
            print("🌐 Private IP - Skipping location lookup.")

# 📱 Lookup MAC from IP (Local only)
def lookup_mac_from_ip(ip):
    print(f"\n🔍 Looking up MAC for IP: {ip}")
    try:
        arp_request = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        result = srp(packet, timeout=3, verbose=0)[0]

        if result:
            mac = result[0][1].hwsrc
            vendor = get_mac_vendor(mac)
            print(f"🔗 MAC Address : {mac}")
            print(f"🍿 Vendor      : {vendor}")
        else:
            print("❌ No device responded to the ARP request.")
    except Exception as e:
        print(f"[!] Error: {e}")

# 🧠 IP Type and Range Info
def get_ip_type_and_range(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private:
            ip_type = "Private"
        elif ip_obj.is_loopback:
            ip_type = "Loopback"
        elif ip_obj.is_multicast:
            ip_type = "Multicast"
        elif ip_obj.is_reserved:
            ip_type = "Reserved"
        elif ip_obj.is_unspecified:
            ip_type = "Unspecified"
        elif ip_obj.is_global:
            ip_type = "Public"
        else:
            ip_type = "Other"

        for net in [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("224.0.0.0/4"),
            ipaddress.ip_network("0.0.0.0/8"),
            ipaddress.ip_network("100.64.0.0/10"),
            ipaddress.ip_network("169.254.0.0/16")
        ]:
            if ip_obj in net:
                dynamic = "Dynamic (Likely DHCP)" if ip_type == "Private" else "Static/Public"
                return ip_type, str(net), dynamic
        return ip_type, "Not in known reserved ranges", "Unknown"
    except Exception as e:
        return "Invalid IP", "-", "-"

# 🔓 Port Scanner
def scan_open_ports(ip, ports):
    print(f"\n🔓 Scanning Open Ports on {ip}")
    print("────────────────────────────────")
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"✅ Port {port} is open")
                open_ports.append(port)
            sock.close()
        except Exception as e:
            print(f"[!] Error scanning port {port}: {e}")
    if not open_ports:
        print("❌ No common ports found open.")

# 🌐 Hostname Lookup
def lookup_hostname(ip):
    print(f"\n🌐 Looking up Hostname for IP: {ip}")
    print("────────────────────────────────")
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        print(f"🖥️ Hostname: {hostname}")
    except Exception as e:
        print(f"❌ Could not resolve hostname: {e}")

# 📘 Main Menu
def main():
    clear()
    print(r"""
  🅿 🅾 🆆 🅴 🆁 🅴 🅳    🅱 🆈    🅲 🅷 🅷 🅰 🆃 🆃 🅸 🆂 🅷                                                                                                                                                               
                                                                                                                                                                     
  NNNNNNN        NNNNNNN                             ttt             SSSSSSSSSSSSSSS                                                   XXXXXXX           XXXXXxX
  N::::::N       N:::::N                          ttt::t           SS:::::::::::::::S                                                   X:::::X         X:::::X
  N:::::::N      N:::::N                          t::::t          S:::::SSSSSS::::::S                                                    X:::::X       X:::::X
  N::::::::N     N:::::N                          t::::t          S:::::S     SSSSSSS                                                     X:::::X     X:::::X
  N:::::::::N    N:::::N    eeeeeeeeeee    ttttttt::::ttttttt    S:::::S                ccccccccccccc  aaaaaaaaaaaaa   nnnn  nnnnnnnn      X::::::X  X:::::X
  N::::::::::N   N:::::N  ee:::::::::::ee  t::::::::::::::::t    S:::::S              cc::::::::::::c  a::::::::::::a  n:::nn::::::::nn     X:::::X X:::::X   
  N::::::N::::N  N:::::N e:::::eeeee:::::eet::::::::::::::::t     S::::SSSS          c::::::::::::::c  aaaaaaaaa:::::a n::::::::::::::nn     X:::::X::::X    
  N:::::N N::::N N:::::Ne:::::e     e:::::etttttt::::::tttttt      SS::::::SSSSS    c::::::ccccc::::c           a::::a nn:::::::::::::::n     X:::::::::X     
  N:::::N  N::::N::::::Ne::::::eeeee::::::e      t::::t              SSS::::::::SS  c:::::c     ccccc    aaaaaaa:::::a   n:::::nnnn:::::n     X:::::::::X     
  N:::::N   N::::::::::Ne::::::::::::::::e       t::::t                 SSSSSS::::S c::::c              a:::::::::::::a  n::::n    n::::n    X:::::X:::::X    
  N:::::N    N:::::::::Ne:::::eeeeeeeeeee        t::::t                      S:::::Sc::::c             a::::aaaa::::::a  n::::n    n::::n   X:::::X X:::::X   
  N:::::N     N::::::::Ne::::::e                 t::::t    tttttt            S:::::Sc:::::c     ccccc a::::a    a:::::a  n::::n    n::::n  X:::::X   X:::::X
  N:::::N      N:::::::Ne:::::::e                t:::::tttt:::::tSSSSSSS     S:::::Sc::::::ccccc::::ca::::a    a:::::a   n::::n    n::::n X:::::X     X:::::X
  N:::::N       N::::::N e:::::::eeeeeeee        tt:::::::::::::tS::::::SSSSSS:::::S c::::::::::::::ca:::::aaaa::::::a   n::::n    n::::nX:::::X       X:::::X
  N:::::N        N:::::N  ee::::::::::::e          tt::::::::::ttS:::::::::::::::SS   cc::::::::::::c a::::::::::aa:::a  n::::n    n::::nX:::::X        X:::::X
  NNNNNNN         NNNNNN    eeeeeeeeeeeee            tttttttttt   SSSSSSSSSSSSSSS       ccccccccccccc  aaaaaaaaaa  aaaa  nnnnnn    nnnnnnXXXXXXX         XXXXXXX

                                                             🔍  Advanced Network Scanner Tool
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
""")
    while True:
        print("\n📋 Menu Options")
        print("────────────────────────────────")
        print("1️⃣  Scan Local Network")
        print("2️⃣  Lookup Public IP Location + ASN")
        print("3️⃣  Lookup MAC from Local IP")
        print("4️⃣  Check IP Type and Range")
        print("5️⃣  Scan Open Ports")
        print("6️⃣  Lookup Hostname from IP")
        print("7️⃣  Exit")
        print("────────────────────────────────")
        choice = input("👉 Enter your choice (1–7): ")

        if choice == '1':
            ip_range = input("📝 Enter IP range (e.g. 192.xxx.x.0/24): ")
            scan(ip_range)
            input("\n⏎ Press Enter to return to menu...")
        elif choice == '2':
            ip = input("🌍 Enter any public IP address: ")
            get_location_from_ip(ip)
            input("\n⏎ Press Enter to return to menu...")
        elif choice == '3':
            ip = input("🔍 Enter local IP address: ")
            lookup_mac_from_ip(ip)
            input("\n⏎ Press Enter to return to menu...")
        elif choice == '4':
            ip = input("🔍 Enter any IP to check type and range: ")
            ip_type, ip_range_block, dynamic = get_ip_type_and_range(ip)
            print(f"\n📄 IP Info")
            print("────────────────────────────────")
            print(f"📌 IP Address   : {ip}")
            print(f"🔎 IP Type      : {ip_type}")
            print(f"📦 IP Range     : {ip_range_block}")
            print(f"🔁 Allocation   : {dynamic}")
            input("\n⏎ Press Enter to return to menu...")
        elif choice == '5':
            ip = input("🔓 Enter IP to scan for open ports: ")
            custom = input("🎯 Do you want full scan (1-65535)? [y/N]: ").lower()
            
            if custom == 'y':
                ports = list(range(1, 65536))
            else:
                ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 3306, 3389]

            scan_open_ports(ip, ports)
            input("\n⏎ Press Enter to return to menu...")

        elif choice == '6':
            ip = input("🌐 Enter IP to lookup hostname: ")
            lookup_hostname(ip)
            input("\n⏎ Press Enter to return to menu...")
        elif choice == '7':
            print("\n👋 Exiting... Thank you for using NetscanX!")
            break
        else:
            print("❌ Invalid input. Try again.")
            input("⏎ Press Enter to continue...")

# ▶️ Entry Point
if __name__ == "__main__":
    main()
