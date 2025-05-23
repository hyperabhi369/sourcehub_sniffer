from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR


def process_packet(packet):
    """Analyze captured packets and print relevant details."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(f"\n[+] Packet: {src_ip} --> {dst_ip} | Protocol: {proto}")

        if packet.haslayer(TCP):
            print(f"    TCP | Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"    UDP | Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}")
        elif packet.haslayer(DNS):
            if packet.haslayer(DNSQR):  # DNS Query
                print(f"    DNS Query | Domain: {packet[DNSQR].qname.decode()}")
            if packet.haslayer(DNSRR):  # DNS Response
                print(f"    DNS Response | Answer: {packet[DNSRR].rdata}")

def main():
    parser = argparse.ArgumentParser(description="Simple Network Sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Specify the network interface (e.g., eth0, wlan0)")
    args = parser.parse_args()

    print(f"[*] Starting sniffer on interface: {args.interface}")
    try:
        sniff(iface=args.interface, store=False, prn=process_packet)
    except PermissionError:
        print("[!] Permission denied. Try running with sudo.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
