__version__ = "1.0.0"
__author__ = "Rorychhatish"

from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from scapy.all import sniff, Ether, IP, ARP, srp
import requests
from mac_vendor_lookup import MacLookup
import os
import ipaddress
import socket
import sys

def check_root():
    if os.geteuid() != 0:
        print("Please run this tool as root (use sudo)")
        sys.exit(1)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_cidr(cidr):
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False
    
def is_linux():
    return os.name == "posix"

# Clear Terminal
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

# Get MAC Vendor Name
def get_mac_vendor(mac):
    try:
        return MacLookup().lookup(mac)
    except:
        return "Unknown Vendor"

# Get Geo Location & ASN Info + VPN/Proxy Detection
def get_location_from_ip(ip):
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=5
        )
        data = response.json()

        print("\n IP LOCATION & ASN INFO")
        print("────────────────────────────────")
        print(f" IP Address   : {data.get('ip')}")
        print(f" City         : {data.get('city')}")
        print(f" Region       : {data.get('region')}")
        print(f" Country      : {data.get('country')}")
        print(f" Coordinates  : {data.get('loc')}")
        print(f" Timezone     : {data.get('timezone')}")

        org = data.get('org', '')
        if org.startswith("AS"):
            asn, as_name = org.split(' ', 1)
            print(f" ASN Number   : {asn}")
            print(f" ASN Provider : {as_name}")
        else:
            print(f" Organization : {org}")

        latlong = data.get("loc")
        if latlong:
            print(f" Google Maps  : https://www.google.com/maps?q={latlong}")

        privacy = data.get("privacy", {})
        if privacy.get("vpn") or privacy.get("proxy") or privacy.get("tor"):
            print(" VPN/Proxy/Tor: Likely in use")
        else:
            print(" VPN/Proxy/Tor: Not detected")

    except Exception as e:
        print(f"[!] Error: {e}")

# Scan Local Network
def scan(ip_range):
    print(f"\n Scanning Local Network Range: {ip_range}")
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
    print(f"\n Connected Devices Found: {len(devices)}")
    print("────────────────────────────────────────────")

    for idx, device in enumerate(devices, 1):
        print(f"\n#{idx}")
        print(f" IP Address  : {device['ip']}")
        print(f" MAC Address : {device['mac']}")
        print(f" Vendor      : {device['vendor']}")
        print(f" Hostname    : {device['hostname']}")

        # Location lookup only for public IPs
        if not device['ip'].startswith(("192.168", "10.", "172.")):
            get_location_from_ip(device['ip'])
        else:
            print(" Private IP - Skipping location lookup.")

# Lookup MAC from IP (Local only)
def lookup_mac_from_ip(ip):
    print(f"\n Looking up MAC for IP: {ip}")
    try:
        arp_request = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        result = srp(packet, timeout=3, verbose=0)[0]

        if result:
            mac = result[0][1].hwsrc
            vendor = get_mac_vendor(mac)
            print(f" MAC Address : {mac}")
            print(f" Vendor      : {vendor}")
        else:
            print(" No device responded to the ARP request.")
    except Exception as e:
        print(f"[!] Error: {e}")

# IP Type and Range Info
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

def scan_single_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            banner = grab_banner(ip, port)
            return port, banner
    except:
        pass
    return None

def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((ip, port))

        # HTTP special case
        if port in [80, 8080, 8000]:
            sock.send(b"HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % ip.encode())
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        if banner:
            return banner
        else:
            return "No banner received"
    except:
        return "Banner grab failed"

# Port Scanner
def scan_open_ports(ip, ports, threads=100):
    print(f"\n Scanning Open Ports on {ip}")
    print("────────────────────────────────")
    open_ports = []
    total_ports = len(ports)
    scanned = 0
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_single_port, ip, port) for port in ports]
        for future in as_completed(futures):
            scanned += 1
            progress = int((scanned / total_ports) * 100)
            print(f"\r Scanning ports... {progress}% complete", end="")
            result = future.result()
            if result:
                port, banner = result
                print(f" \n Port {port} is open")
                print(f"    ↳ Banner: {banner}")
                open_ports.append(port)
    print("\n────────────────────────────────")
    if not open_ports:
        print(" No open ports found.")
    else:
        print(f" Open Ports: {open_ports}")

# Hostname Lookup
def lookup_hostname(ip):
    print(f"\n Looking up Hostname for IP: {ip}")
    print("────────────────────────────────")
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        print(f"🖥️ Hostname: {hostname}")
    except Exception as e:
        print(f" Could not resolve hostname: {e}")

def passive_sniffer():
    print("\n Passive Sniffer Started (Stealth Mode)")
    print(" No ARP • No Ping • No Noise ")
    print("\n MAC Address          | IP Address           | TTL | OS Guess")
    print("──────────────────────────────────────────────────────────")
    seen_devices = set()
    def process_packet(packet):
        try:
            if packet.haslayer(Ether) and packet.haslayer(IP):
                src_mac = packet[Ether].src
                src_ip = packet[IP].src
                ttl = packet[IP].ttl
                os_guess = guess_os_from_ttl(ttl)
                if (src_mac, src_ip) not in seen_devices:
                    seen_devices.add((src_mac, src_ip))
                    print(f" {src_mac:<21} | {src_ip:<15} | TTL:{ttl:<3} | {os_guess}")
        except:
            pass
    sniff(prn=process_packet, store=False, filter="ip")

def guess_os_from_ttl(ttl):
    if ttl >= 128:
        return "Likely Windows"
    elif ttl >= 64:
        return "Likely Linux / Android"
    elif ttl >= 255:
        return "Likely Network Device"
    else:
        return "Unknown"

# Main Menu
def main():
    check_root()
    clear()
    print(r"""
  🅿 🅾 � 🅴 � 🅴 🅳    🅱 🆈    🅲 🅷 🅷 🅰 🆃 🆃 🅸 🆂 🅷                                                                                                                                                               
                                                                                                                                                                     
  NNNNNN        NNNNNNN                          tttttt           SSSSSSSSSSSSSSS                                                   XXXXXXX           XXXXXxX
  N:::::N       N:::::N                          t::::t         SS:::::::::::::::S                                                   X:::::X         X:::::X
  N::::::N      N:::::N                          t::::t        S:::::SSSSSS::::::S                                                    X:::::X       X:::::X
  N:::::::N     N:::::N                          t::::t        S:::::S     SSSSSSS                                                     X:::::X     X:::::X
  N::::::::N    N:::::N    eeeeeeeeeee    ttttttt::::ttttttt  S:::::S                cccccccccccc  aaaaaaaaaaaaa   nnnn  nnnnnnnn      X::::::X  X:::::X
  N:::::::::N   N:::::N  ee:::::::::::ee  t::::::::::::::::t  S:::::S              cc:::::::::::c  a::::::::::::a  n:::nn::::::::nn     X:::::X X:::::X   
  N:::::N::::N  N:::::N e:::::eeeee:::::eet::::::::::::::::t   S::::SSSS          c:::::::::::::c  aaaaaaaaa:::::a n::::::::::::::nn     X:::::X::::X    
  N::::N N::::N N:::::Ne:::::e     e:::::etttttt::::::tttttt    SS::::::SSSSS    c::::::cccc::::c           a::::a nn:::::::::::::::n     X:::::::::X     
  N::::N  N::::N::::::Ne::::::eeeee::::::e      t::::t            SSS::::::::SS  c:::::c    ccccc    aaaaaaa:::::a   n:::::nnnn:::::n     X:::::::::X     
  N::::N   N::::::::::Ne::::::::::::::::e       t::::t               SSSSSS::::S c::::c             a:::::::::::::a  n::::n    n::::n    X:::::X:::::X    
  N::::N    N:::::::::Ne:::::eeeeeeeeeee        t::::t                    S:::::Sc::::c            a::::aaaa::::::a  n::::n    n::::n   X:::::X X:::::X   
  N::::N     N::::::::Ne::::::e                 t::::t    ttttt           S:::::Sc:::::c    ccccc a::::a    a:::::a  n::::n    n::::n  X:::::X   X:::::X
  N::::N      N:::::::Ne:::::::e                t:::::tttt::::t SSSSSS     S:::::Sc::::::cccc:::ca::::a    a:::::a   n::::n    n::::n X:::::X     X:::::X
  N::::N       N::::::N e:::::::eeeeeeee        tt::::::::::::tS:::::SSSSSS:::::S c:::::::::::::c a:::::aaaa::::::a   n::::n    n::::nX:::::X       X:::::X
  N::::N        N:::::N  ee::::::::::::e          tt:::::::::ttS::::::::::::::SS   cc:::::::::::c a::::::::::aa:::a  n::::n    n::::nX:::::X        X:::::X
  NNNNNN         NNNNNN    eeeeeeeeeeeee            ttttttttt   SSSSSSSSSSSSSS       cccccccccccc  aaaaaaaaaa  aaaa  nnnnnn    nnnnnnXXXXXXX         XXXXXXX

                                                                  Advanced Network Scanner Tool
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
""")
    while True:
        print("\n Menu Options")
        print("────────────────────────────────")
        print("1  Scan Local Network")
        print("2  Lookup Public IP Location + ASN")
        print("3  Lookup MAC from Local IP")
        print("4  Check IP Type and Range")
        print("5  Scan Open Ports")
        print("6  Lookup Hostname from IP")
        print("7  Passive Sniffer (Stealth Mode)")
        print("99 Exit")
        print("────────────────────────────────")
        choice = input(" Enter your choice : ")

        if choice == '1':
            ip_range = input(" Enter IP range (e.g. 192.xxx.x.0/24): ")
            if not validate_cidr(ip_range):
                print("❌ Invalid IP range format")
                input("⏎ Press Enter to continue...")
                continue
            scan(ip_range)
            input("\n⏎ Press Enter to return to menu...")
        elif choice == '2':
            ip = input(" Enter any public IP address: ")
            if not validate_ip(ip):
                print("❌ Invalid IP address")
                input("⏎ Press Enter to continue...")
                continue
            get_location_from_ip(ip)
            input("\n⏎ Press Enter to return to menu...")
        elif choice == '3':
            ip = input(" Enter local IP address: ")
            if not validate_ip(ip):
                print("❌ Invalid IP address")
                input("⏎ Press Enter to continue...")
                continue
            lookup_mac_from_ip(ip)
            input("\n⏎ Press Enter to return to menu...")
        elif choice == '4':
            ip = input(" Enter any IP to check type and range: ")
            if not validate_ip(ip):
                print("❌ Invalid IP address")
                input("⏎ Press Enter to continue...")
                continue
            ip_type, ip_range_block, dynamic = get_ip_type_and_range(ip)
            print(f"\n📄 IP Info")
            print("────────────────────────────────")
            print(f" IP Address   : {ip}")
            print(f" IP Type      : {ip_type}")
            print(f" IP Range     : {ip_range_block}")
            print(f" Allocation   : {dynamic}")
            input("\n⏎ Press Enter to return to menu...")
       
        elif choice == '5':
            ip = input(" Enter IP to scan for open ports: ")
            if not validate_ip(ip):
                print("❌ Invalid IP address")
                input("⏎ Press Enter to continue...")
                continue
            custom = input(" Do you want full scan (1-65535)? [y/N]: ").lower()
            if custom == 'y':
                ports = list(range(1, 65536))
            else:
                ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                 443, 445, 587, 993, 995, 3306, 3389]
            scan_open_ports(ip, ports)
            input("\n⏎ Press Enter to return to menu...")

        elif choice == '6':
            ip = input(" Enter IP to lookup hostname: ")
            if not validate_ip(ip):
                print("❌ Invalid IP address")
                input("⏎ Press Enter to continue...")
                continue
            lookup_hostname(ip)
            input("\n⏎ Press Enter to return to menu...")

        elif choice == '7':
            passive_sniffer()
            input("\n⏎ Press Enter to return to menu...")

        elif choice == '99':
            print("\n Exiting... Thank you for using NetscanX!!!")
            break

        else:
            print("❌ Invalid input. Try again.")
            input("⏎ Press Enter to continue...")
# Entry Point
if __name__ == "__main__":
    main()
