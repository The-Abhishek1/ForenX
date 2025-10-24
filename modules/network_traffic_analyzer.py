from scapy.all import rdpcap, IP, TCP, Raw
from typing import List

# ========== Extract_Unique_IPS ====
def extract_unique_ips(pcap_path: str) -> List[str]:
    packets = rdpcap(pcap_path)
    ips: Set[str] = set()
    
    for pkt in packets:
        if IP in pkt:
            ips.add(pkt[IP].src)
            ips.add(pkt[IP].dst)
        
    return sorted(ips)

# =========== Main =================
def main(pcap_path: str):
    ips = extract_unique_ips(pcap_path)
    print(f"[+] Found {len(ips)} unique IPs.")
    for ip in ips:
        print(" ",ip)
    
    

# ============ __main__ ============
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Network analyzer - extract unique IPs from pcap")
    parser.add_argument("-i", "--input", required=True, help="Path to .pcap file")
    args = parser.parse_args()
    
    main(args.input)