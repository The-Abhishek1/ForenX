# modules/network_traffic_analyzer.py

from scapy.all import rdpcap, IP, TCP, Raw
from typing import List, Tuple
from collections import Counter
import base64
import re
import binascii



# regexes (keep existing)
CRED_PAYLOAD_RE = re.compile(rb'(?i)(?:username|user|login|email)[:=]\s*([^\s&\'"<>]{3,100})')
PASS_PAYLOAD_RE = re.compile(rb'(?i)(?:password|passwd|pwd|pass)[:=]\s*([^\s&\'"<>]{3,200})')
AUTH_BASIC_RE = re.compile(rb'Authorization:\s*Basic\s+([A-Za-z0-9+/=._-]{8,})', re.IGNORECASE)
FORM_FIELD_RE = re.compile(rb'([\w\-\.\[\]]+)=([^&\s]{1,200})')

# ====================== Printable_Ratio ==========================
def printable_ratio(b: bytes) -> float:
    """Return fraction of bytes that are ASCII-printable (32-126)"""
    if not b:
        return 0.0
    printable = sum(1 for x in b if 32 <= x <= 126)
    return printable / len(b)
# ====================== Clean_Snippet ============================
def clean_snippet(b: bytes, maxlen: int = 200) -> str:
    """Decode bytes ignoring errors, keep printable chars only and truncate."""
    s = b.decode('utf-8', errors='ignore')
    # keep only printable ascii
    filtered = ''.join(ch for ch in s if 32 <= ord(ch) <= 126)
    return (filtered[:maxlen] + '...') if len(filtered) > maxlen else filtered

# ====================== Decode_Basic_Auth ========================
def decode_basic_auth(b64token: str) -> Tuple[str, str]:
    try:
        raw = base64.b64decode(b64token + '==')
        parts = raw.decode(errors='ignore').split(':', 1)
        if len(parts) == 2:
            return parts[0], parts[1]
    except (binascii.Error, Exception):
        pass
    return "", ""

# ================= Detect_Credential_Leaks ========================
def detect_credential_leaks(pcap_path: str, printable_threshold: float = 0.6) -> List[str]:
    """
    - Requires TCP layer
    - Filters payloads by printable ASCII ratio and HTTP/form heuristics
    - Detects Basic auth, username/password patterns, and form fields
    """
    packets = rdpcap(pcap_path)
    alerts: List[str] = []
    seen = set()

    for idx, pkt in enumerate(packets):
        # require IP + TCP + Raw
        if not (IP in pkt and TCP in pkt and Raw in pkt):
            continue

        payload: bytes = bytes(pkt[Raw].load)
        if len(payload) < 10:
            continue

        # quick printable filter to avoid binary/TLS payloads
        pr = printable_ratio(payload)
        if pr < printable_threshold:
            continue

        # only proceed if looks like HTTP/form data or contains '=' (heuristic)
        looks_like_http = payload.startswith(b'GET ') or payload.startswith(b'POST ') or b'HTTP/' in payload[:10] or b'Host:' in payload[:20]
        has_form_like = b'=' in payload and (b'&' in payload or b'=' in payload)
        if not (looks_like_http or has_form_like):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        # decode once and create cleaned snippet
        snippet = clean_snippet(payload, maxlen=300)

        # Authorization: Basic
        m_auth = AUTH_BASIC_RE.search(payload)
        if m_auth:
            token = m_auth.group(1).decode(errors='ignore')
            user, pwd = decode_basic_auth(token)
            key = ("auth_basic", user, pwd, idx)
            if key not in seen:
                seen.add(key)
                alerts.append(f"[AUTH_BASIC] pkt#{idx} {src}:{sport}->{dst}:{dport} user={user} pwd={pwd} | {snippet}")

        # username/password patterns
        for m in CRED_PAYLOAD_RE.finditer(payload):
            val = m.group(1).decode(errors='ignore')
            key = ("cred", val, idx)
            if key not in seen:
                seen.add(key)
                alerts.append(f"[CRED] pkt#{idx} {src}:{sport}->{dst}:{dport} value={val} | {snippet}")

        for m in PASS_PAYLOAD_RE.finditer(payload):
            val = m.group(1).decode(errors='ignore')
            key = ("pass", val, idx)
            if key not in seen:
                seen.add(key)
                alerts.append(f"[PASS] pkt#{idx} {src}:{sport}->{dst}:{dport} value={val} | {snippet}")

        # form extraction but only show if key looks credential-like
        for m in FORM_FIELD_RE.finditer(payload):
            k = m.group(1).decode(errors='ignore')
            v = m.group(2).decode(errors='ignore')
            if any(x in k.lower() for x in ("user", "pass", "token", "auth", "pwd")) or len(v) > 40:
                key = ("form", k, v, idx)
                if key not in seen:
                    seen.add(key)
                    alerts.append(f"[FORM] pkt#{idx} {src}:{sport}->{dst}:{dport} {k}={v} | {snippet}")

    if not alerts:
        alerts.append("[OK] No credential-like strings detected (filtered).")

    return alerts
 


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
def analyze(pcap_path: str):
    results = []
    results.append("[*] Analyzing the PCAP file...\n")
    ips = extract_unique_ips(pcap_path)
    results.append(f"[+] Found {len(ips)} unique IPs.")
    for ip in ips:
        results.append(f"   {ip}")
    
    results.append(f"\n[+] Top destination ports:")
    for port, count in summarize_sorts(pcap_path):
        results.append(f"    Port {port} - {count} packets")
    
    results.append(f"\n[+] Scannig for suspicious ports...")
    for alert in detect_suspicious_ports(pcap_path):
        results.append(f"    {alert}")
        
    results.append(f"\n[+] Scanning for credential leaks in payloads...")
    for alert in detect_credential_leaks(pcap_path):
        results.append(f"    {alert}")

    return results