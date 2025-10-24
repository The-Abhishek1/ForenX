from scapy.all import rdpcap, IP, TCP, Raw
from typing import List
from collections import Counter


# =============== Detect_Suspicious_Ports ==========================
def detect_suspicious_ports(pcap_path: str) -> List[str]:
    """This function detects suspicious ports"""
    suspicious_ports = {22, 445, 3389, 4444, 1337, 8080, 9001, 8443}
    packets = rdpcap(pcap_path)
    alerts = []
    
    for pkt in packets:
        if TCP in pkt and IP in pkt:
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            if dport in suspicious_ports:
                alerts.append(f"[!] Suspicious connection: {src}:{sport} -> {dst}:{dport}")
                
    if not alerts:
        alerts.append(f"[OK] No suspicious ports detected.")
    
    alerts.append("\n")
    return alerts


# =============== Summarize_Ports ==================================
def summarize_sorts(pcap_path: str, top_n: int = 5) ->  List[tuple]:
    """This Function returns tops N used TCP destination ports."""
    packets = rdpcap(pcap_path)
    port_counter = Counter()
    
    for pkt in packets:
        if TCP in pkt and IP in pkt:
            dport = pkt[TCP].dport
            port_counter[dport] +=1
    
    return port_counter.most_common(top_n)
    

# ============== Extract_Unique_IPS ==============================
def extract_unique_ips(pcap_path: str) -> List[str]:  
    """This Function returns unique IPS found in pcap file."""
    packets = rdpcap(pcap_path)
    ips: Set[str] = set()
    
    for pkt in packets:
        if IP in pkt:
            ips.add(pkt[IP].src)
            ips.add(pkt[IP].dst)
        
    return sorted(ips)

# ============== Main ============================================
def main(pcap_path: str):
    print(f"[*] Analyzing the PCAP file...\n")
    ips = extract_unique_ips(pcap_path)
    print(f"[+] Found {len(ips)} unique IPs.")
    for ip in ips:
        print("   ",ip)
    
    print(f"\n[+] Top destination ports:")
    for port, count in summarize_sorts(pcap_path):
        print(f"    Port {port} - {count} packets")
    
    print(f"\n[+] Scannig for suspicious ports...")
    for alert in detect_suspicious_ports(pcap_path):
        print(f"    {alert}")
    

# ============= __main__ =========================================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Network analyzer - extract unique IPs from pcap")
    parser.add_argument("-i", "--input", required=True, help="Path to .pcap file")
    args = parser.parse_args()
    
    main(args.input)