# modules/memory_analyzer.py

from typing import List, Iterable, Tuple
import re
from collections import Counter
import math

# ----------------------------
# Config / Regex patterns
# ----------------------------
# Printable ASCII considered in extracted strings
PRINTABLE = set(range(32, 127))

# Minimal string length to consider (reduce noise)
MIN_STR_LEN = 6

# Chunk size for streaming reads
CHUNK_SIZE = 1024 * 1024  # 1 MiB

# Regex patterns (bytes mode when scanning raw bytes)
IPV4_RE = re.compile(rb'\b(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})){3}\b')
IPV6_RE = re.compile(rb'\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b')
EMAIL_RE = re.compile(rb'\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,}\b')
URL_RE = re.compile(rb'https?://[^\s\'"<>]{6,512}')
# credential-ish patterns: password=, pwd:, pass:, secret=, api_key= etc.
CRED_RE_LIST = [
    re.compile(rb'(?i)(password|passwd|pwd|pass|secret|api_key|apikey|token)[:=]\s*([^\s;\'"\\]{4,200})'),
    re.compile(rb'(?i)(user|username)[:=]\s*([A-Za-z0-9._\-]{2,100})')
]
# JWT-like: three base64url parts separated by dots (header.payload.signature)
JWT_RE = re.compile(rb'([A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})')
# API-key heuristics: long hex or base64-like tokens
APIKEY_HEUR = re.compile(rb'\b([A-Fa-f0-9]{32,}|[A-Za-z0-9_\-]{32,})\b')
# SSH key marker
SSH_KEY_RE = re.compile(rb'(ssh-(rsa|dss|ed25519)|-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----)')

# ----------------------------
# Utility: entropy calculation
# ----------------------------
def shannon_entropy(data: str) -> float:
    """
    Compute Shannon entropy of a string (based on characters).
    Useful to detect likely random keys (high entropy).
    """
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent

# ----------------------------
# Extract printable ASCII strings from a binary stream (generator)
# ----------------------------
def extract_ascii_strings_from_stream(fobj, min_len: int = MIN_STR_LEN, chunk_size: int = CHUNK_SIZE) -> Iterable[bytes]:
    """
    Generator yielding printable ASCII strings (bytes) found in a binary stream.
    Works incrementally; good for large memory dumps.
    """
    buf = bytearray()
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            if len(buf) >= min_len:
                yield bytes(buf)
            break

        for b in chunk:
            if b in PRINTABLE:
                buf.append(b)
            else:
                if len(buf) >= min_len:
                    yield bytes(buf)
                buf.clear()
        # continue reading

# ----------------------------
# Finders
# ----------------------------
def find_ips(path: str, max_items: int = 50) -> List[Tuple[str, int]]:
    """Return top IPv4/v6 candidates with counts."""
    ips = []
    with open(path, "rb") as f:
        for s in extract_ascii_strings_from_stream(f):
            for m in IPV4_RE.finditer(s):
                try:
                    ips.append(m.group().decode('utf-8', errors='ignore'))
                except Exception:
                    ips.append(m.group().decode(errors='ignore'))
            for m in IPV6_RE.finditer(s):
                try:
                    ips.append(m.group().decode('utf-8', errors='ignore'))
                except Exception:
                    ips.append(m.group().decode(errors='ignore'))
    return Counter(ips).most_common(max_items)

def find_emails(path: str, max_items: int = 50) -> List[Tuple[str, int]]:
    emails = []
    with open(path, "rb") as f:
        for s in extract_ascii_strings_from_stream(f):
            for m in EMAIL_RE.finditer(s):
                emails.append(m.group().decode(errors='ignore'))
    return Counter(emails).most_common(max_items)

def find_urls(path: str, max_items: int = 50) -> List[Tuple[str, int]]:
    urls = []
    with open(path, "rb") as f:
        for s in extract_ascii_strings_from_stream(f):
            for m in URL_RE.finditer(s):
                urls.append(m.group().decode(errors='ignore'))
    return Counter(urls).most_common(max_items)

def find_credentials(path: str, max_items: int = 100) -> List[Tuple[str, int, str]]:
    """
    Return tuples: (credential_value, count, sample_context)
    """
    found = []
    with open(path, "rb") as f:
        for s in extract_ascii_strings_from_stream(f, min_len=8):
            for cre in CRED_RE_LIST:
                for m in cre.finditer(s):
                    # group 1 = key name, group 2 = value for first pattern
                    groups = m.groups()
                    # prefer the captured value if present
                    if len(groups) >= 2 and groups[1]:
                        val_b = groups[1]
                    else:
                        # fallback: entire match
                        val_b = m.group()
                    try:
                        val = val_b.decode(errors='ignore')
                    except Exception:
                        val = repr(val_b)
                    # snippet for context
                    snippet = s.decode(errors='ignore')
                    found.append((val, snippet[:200]))
    # aggregate counts and attach an example snippet
    vals = [v for v, _ in found]
    counts = Counter(vals)
    results = []
    for k, cnt in counts.most_common(max_items):
        snippet = next((sn for v, sn in found if v == k), "")
        results.append((k, cnt, snippet))
    return results

def find_jwts_and_tokens(path: str, max_items: int = 50) -> List[Tuple[str, int]]:
    toks = []
    with open(path, "rb") as f:
        for s in extract_ascii_strings_from_stream(f, min_len=20):
            for m in JWT_RE.finditer(s):
                toks.append(m.group().decode(errors='ignore'))
            for m in APIKEY_HEUR.finditer(s):
                candidate = m.group().decode(errors='ignore')
                # heuristic: length and presence of base64-like characters or hex
                if len(candidate) >= 32:
                    toks.append(candidate)
    return Counter(toks).most_common(max_items)

def find_ssh_keys(path: str, max_items: int = 10) -> List[str]:
    keys = []
    with open(path, "rb") as f:
        for s in extract_ascii_strings_from_stream(f, min_len=40):
            if SSH_KEY_RE.search(s):
                try:
                    keys.append(s.decode(errors='ignore')[:1500])
                except Exception:
                    keys.append(repr(s)[:1500])
    return keys[:max_items]

def find_high_entropy_strings(path: str, max_items: int = 50, entropy_threshold: float = 4.0) -> List[Tuple[str, float]]:
    """
    Detect high-entropy strings which are likely keys or binary blobs embedded as printable.
    entropy_threshold: typical text has entropy < ~4.5, random keys > ~4.5-4.8 (heuristic)
    """
    candidates = []
    with open(path, "rb") as f:
        for s in extract_ascii_strings_from_stream(f, min_len=20):
            try:
                txt = s.decode(errors='ignore')
            except Exception:
                continue
            ent = shannon_entropy(txt)
            if ent >= entropy_threshold:
                # keep moderate-length strings to reduce noise
                if 20 <= len(txt) <= 2000:
                    candidates.append((txt[:300], ent))
    # sort by entropy desc
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[:max_items]

# ----------------------------
# High-level analyze() function
# ----------------------------
def analyze(path: str) -> List[str]:
    """
    High-level memory triage. Returns a list of strings (report lines).
    """
    report: List[str] = []
    report.append("===== ForenX Memory Triage Report =====")
    report.append(f"Target file: {path}")

    # 1) IP addresses
    report.append("\n[1] IP Address Candidates (top 30):")
    try:
        ips = find_ips(path, max_items=30)
    except Exception as e:
        report.append(f"  [ERROR] IP scan failed: {e}")
        ips = []
    if ips:
        for ip, cnt in ips:
            report.append(f"  {ip} - {cnt} occurrence(s)")
    else:
        report.append("  [None found]")

    # 2) Emails
    report.append("\n[2] Email Candidates (top 30):")
    try:
        emails = find_emails(path, max_items=30)
    except Exception as e:
        report.append(f"  [ERROR] Email scan failed: {e}")
        emails = []
    if emails:
        for em, cnt in emails:
            report.append(f"  {em} - {cnt}")
    else:
        report.append("  [None found]")

    # 3) URLs
    report.append("\n[3] URL Candidates (top 30):")
    try:
        urls = find_urls(path, max_items=30)
    except Exception as e:
        report.append(f"  [ERROR] URL scan failed: {e}")
        urls = []
    if urls:
        for u, cnt in urls:
            report.append(f"  {u} - {cnt}")
    else:
        report.append("  [None found]")

    # 4) Credential-like strings
    report.append("\n[4] Credential-like Candidates (top 50):")
    try:
        creds = find_credentials(path, max_items=50)
    except Exception as e:
        report.append(f"  [ERROR] Credential scan failed: {e}")
        creds = []
    if creds:
        for val, cnt, snippet in creds:
            report.append(f"  Value: {val} - {cnt} occurrence(s)")
            if snippet:
                snippet_clean = snippet.replace("\n", " ")
                report.append(f"    Context: {snippet_clean}")
    else:
        report.append("  [None found]")

    # 5) JWTs / tokens / api-keys
    report.append("\n[5] JWT / Token Candidates (heuristic):")
    try:
        toks = find_jwts_and_tokens(path, max_items=50)
    except Exception as e:
        report.append(f"  [ERROR] Token scan failed: {e}")
        toks = []
    if toks:
        for t, cnt in toks:
            report.append(f"  Token: {t} - {cnt}")
    else:
        report.append("  [None found]")

    # 6) SSH / private key markers
    report.append("\n[6] SSH / Key Artefacts (first matches):")
    try:
        keys = find_ssh_keys(path, max_items=10)
    except Exception as e:
        report.append(f"  [ERROR] Key scan failed: {e}")
        keys = []
    if keys:
        for i, k in enumerate(keys, 1):
            report.append(f"  Key-snippet-{i}: {k[:1000]}")
    else:
        report.append("  [None found]")

    # 7) High-entropy strings
    report.append("\n[7] High-entropy printable strings (possible keys):")
    try:
        high_e = find_high_entropy_strings(path, max_items=30, entropy_threshold=4.3)
    except Exception as e:
        report.append(f"  [ERROR] Entropy scan failed: {e}")
        high_e = []
    if high_e:
        for txt, ent in high_e:
            report.append(f"  Entropy={ent:.2f} | Sample: {txt[:200]}")
    else:
        report.append("  [None found]")

    # Summary counts
    report.append("\n[Summary]")
    report.append(f"  IP candidates: {len(ips)}")
    report.append(f"  Email candidates: {len(emails)}")
    report.append(f"  URL candidates: {len(urls)}")
    report.append(f"  Credential candidates: {len(creds)}")
    report.append(f"  Token/jwt candidates: {len(toks)}")
    report.append(f"  SSH/key artefacts: {len(keys)}")
    report.append(f"  High-entropy candidates: {len(high_e)}")

    return report
