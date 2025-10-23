# modules/memory_analyzer.py
import re
from collections import Counter

# Regexes we care about
IP_RE = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PWD_RES = [
    re.compile(rb'password[:=]\s*([^\s;\'"\\\x00]{4,100})', re.IGNORECASE),
    re.compile(rb'pass[:=]\s*([^\s;\'"\\\x00]{4,100})', re.IGNORECASE),
    re.compile(rb'pwd[:=]\s*([^\s;\'"\\\x00]{4,100})', re.IGNORECASE),
]
SSH_KEY_RE = re.compile(rb'(ssh-(rsa|dss|ed25519)|-----BEGIN RSA PRIVATE KEY-----|BEGIN OPENSSH PRIVATE KEY|ssh-rsa|ssh-ed25519)')

PRINTABLE = set(range(32, 127))  # ASCII printable

def _extract_ascii_strings_from_stream(fobj, min_len=6, chunk_size=1024*1024):
    """
    Generator that yields printable ASCII strings (bytes) found in a binary stream.
    Works in streaming way so it can handle big files.
    """
    buf = bytearray()
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            # flush
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

def find_ips_in_file(path, max_items=50):
    ips = []
    with open(path, 'rb') as f:
        for s in _extract_ascii_strings_from_stream(f, min_len=7):
            for m in IP_RE.finditer(s):
                ips.append(m.group().decode(errors='ignore'))
    return Counter(ips).most_common(max_items)

def find_password_candidates(path, max_items=100):
    found = []
    with open(path, 'rb') as f:
        for s in _extract_ascii_strings_from_stream(f, min_len=6):
            for regex in PWD_RES:
                for m in regex.finditer(s):
                    # group 1 is the candidate password/value
                    try:
                        val = m.group(1).decode(errors='ignore')
                    except Exception:
                        val = repr(m.group(1))
                    # We capture surrounding snippet to give context
                    snippet = s.decode(errors='ignore', errors='ignore')
                    found.append((val, snippet[:200]))
    # dedupe and order by occurrence
    vals = [v for v, _ in found]
    counts = Counter(vals)
    res = []
    for k, cnt in counts.most_common(max_items):
        # find a snippet for this k
        snippet = next((sn for v, sn in found if v == k), "")
        res.append((k, cnt, snippet))
    return res

def find_ssh_keys(path, max_items=20):
    hits = []
    with open(path, 'rb') as f:
        for s in _extract_ascii_strings_from_stream(f, min_len=20):
            if SSH_KEY_RE.search(s):
                try:
                    txt = s.decode(errors='ignore')
                except:
                    txt = str(s)
                hits.append(txt[:1000])  # truncate long keys for safety
    return hits[:max_items]

def analyze(path):
    """
    High-level analyzer: returns a list of human-friendly lines summarizing findings.
    """
    report = []
    report.append("===== ForenX Memory Analysis Report =====")
    report.append(f"Target file: {path}")

    report.append("\n[1] IP Address Candidates (top 20):")
    ips = find_ips_in_file(path, max_items=20)
    if ips:
        for ip, cnt in ips:
            report.append(f"  {ip} - {cnt} occurrence(s)")
    else:
        report.append("  [None found]")

    report.append("\n[2] Password-like Candidates (top 20):")
    pwds = find_password_candidates(path, max_items=20)
    if pwds:
        for val, cnt, snippet in pwds:
            report.append(f"  Value: {val} - {cnt} occurrence(s)")
            # show small context for analyst
            if snippet:
                report.append(f"    Context snippet: {snippet[:200].replace('\\n',' ')}")
    else:
        report.append("  [None found]")

    report.append("\n[3] SSH / Key Artefacts (first matches):")
    keys = find_ssh_keys(path, max_items=10)
    if keys:
        for i, k in enumerate(keys, 1):
            report.append(f"  Key-snippet-{i}: {k[:500]}")
    else:
        report.append("  [None found]")

    # brief stats
    report.append("\n[Summary]")
    report.append(f"  IP candidates found: {len(ips)}")
    report.append(f"  Password-like candidates found: {len(pwds)}")
    report.append(f"  SSH/key artefacts found: {len(keys)}")

    return report
