# modules/file_extractor.py

# modules/file_extractor.py
"""
ForenX - File Artifact Extractor
Scans a directory (or mounted image) for files, computes metadata and hashes,
and flags suspicious files based on simple heuristics (executable headers, suspicious extensions,
hidden files, location like /tmp, recent modification, large size).
"""

from typing import List, Dict, Tuple, Optional, Iterable
import os
import hashlib
import mimetypes
from pathlib import Path
from collections import Counter
import csv
import json
import time
from datetime import datetime, timedelta

# ---------------------------
# Config / heuristics
# ---------------------------
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".sh", ".py", ".jar", ".bin", ".elf"
}
TEMP_DIR_INDICATORS = {"/tmp", "/var/tmp", "\\\\Temp\\"} 
LARGE_FILE_BYTES = 100 * 1024 * 1024
RECENT_DAYS = 7 

# ---------------------------
# Utility functions
# ---------------------------
def compute_hashes(path: str, algorithms: Optional[List[str]] = None) -> Dict[str, str]:
    if algorithms is None:
        algorithms = ["md5", "sha1", "sha256"]

    hash_objs = {}
    for a in algorithms:
        if a.lower() == "md5":
            hash_objs["md5"] = hashlib.md5()
        elif a.lower() == "sha1":
            hash_objs["sha1"] = hashlib.sha1()
        elif a.lower() == "sha256":
            hash_objs["sha256"] = hashlib.sha256()
        else:
            continue

    # read in chunks
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                for h in hash_objs.values():
                    h.update(chunk)
    except Exception as e:
        # on error return empty strings
        return {k: "" for k in hash_objs.keys()}

    return {k: v.hexdigest() for k, v in hash_objs.items()}


def get_basic_file_info(path: str) -> Dict[str, object]:
    p = Path(path)
    stat = p.stat()
    size = stat.st_size
    mtime = datetime.fromtimestamp(stat.st_mtime)
    atime = datetime.fromtimestamp(stat.st_atime)
    ctime = datetime.fromtimestamp(stat.st_ctime)
    ext = p.suffix.lower()
    mime, _ = mimetypes.guess_type(path)
    is_exec_bit = os.access(path, os.X_OK)

    return {
        "path": str(p.resolve()),
        "name": p.name,
        "size": size,
        "mtime": mtime.isoformat(),
        "atime": atime.isoformat(),
        "ctime": ctime.isoformat(),
        "extension": ext,
        "mimetype": mime or "unknown",
        "is_executable_bit": is_exec_bit,
    }


def read_magic_bytes(path: str, num: int = 512) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(num)
    except Exception:
        return b""


def check_magic_header(path: str) -> Optional[str]:
    """
    Inspect the file header and return a short marker if known:
      - 'ELF'  -> ELF binary (Linux)
      - 'PE'   -> PE (Windows) (MZ)
      - 'ZIP'  -> ZIP/JAR
      - 'PDF'  -> PDF
      - None   -> unknown / not recognized
    """
    head = read_magic_bytes(path, 8)
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head.startswith(b"MZ"):
        return "PE"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP"
    if head.startswith(b"%PDF"):
        return "PDF"
    return None


# ---------------------------
# Suspicion heuristics
# ---------------------------
def is_in_temp_dir(path: str) -> bool:
    lower = path.lower()
    for t in TEMP_DIR_INDICATORS:
        if t.lower() in lower:
            return True
    return False


def is_recent(mtime_iso: str, days: int = RECENT_DAYS) -> bool:
    try:
        m = datetime.fromisoformat(mtime_iso)
    except Exception:
        return False
    return (datetime.now() - m) <= timedelta(days=days)


def evaluate_suspicion(path: str, info: Dict[str, object]) -> Tuple[bool, List[str]]:
    """
    Heuristics:
      - suspicious extension
      - file in temp dir
      - executable header detected (ELF/PE)
      - executable bit set
      - large file size
      - recently modified
      - hidden filename (starts with .)
    """
    reasons: List[str] = []
    ext = info.get("extension", "")
    size = info.get("size", 0)
    mtime = info.get("mtime", "")
    name = info.get("name", "")

    magic = check_magic_header(path)
    if ext in SUSPICIOUS_EXTENSIONS:
        reasons.append(f"suspicious_extension:{ext}")
    if is_in_temp_dir(path):
        reasons.append("in_temp_directory")
    if magic:
        reasons.append(f"header:{magic}")
    if info.get("is_executable_bit", False):
        reasons.append("exec_bit_set")
    if size and size >= LARGE_FILE_BYTES:
        reasons.append(f"large_file:{size}")
    if is_recent(mtime):
        reasons.append(f"recently_modified:{mtime}")
    if name.startswith("."):
        reasons.append("hidden_filename")

    return (len(reasons) > 0, reasons)


# ---------------------------
# Directory walk & analysis
# ---------------------------
def iterate_files(root: str, follow_symlinks: bool = False) -> Iterable[str]:
    root_p = Path(root)
    if not root_p.exists():
        return

    for dirpath, dirs, files in os.walk(root, followlinks=follow_symlinks):
        for fname in files:
            fp = os.path.join(dirpath, fname)
            yield fp


def analyze_path(root: str, limit: Optional[int] = None) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    count = 0
    for fp in iterate_files(root):
        try:
            basic = get_basic_file_info(fp)
        except Exception:
            continue

        # optional limit for fast testing
        if limit and count >= limit:
            break
        count += 1

        # hashes (compute for small files or as needed)
        hashes = compute_hashes(fp, algorithms=["md5", "sha1", "sha256"])
        magic = check_magic_header(fp)
        suspicious, reasons = evaluate_suspicion(fp, basic)

        row = {
            **basic,
            **hashes,
            "magic_header": magic or "",
            "suspicious": suspicious,
            "reasons": reasons,
        }
        results.append(row)

    return results


# ---------------------------
# Reporting / export
# ---------------------------
def generate_csv_report(results: List[Dict[str, object]], outpath: str) -> None:
    """
    Save results to CSV. Columns chosen for easy reading.
    """
    if not results:
        return
    keys = [
        "path", "name", "size", "mtime", "extension", "mimetype",
        "md5", "sha1", "sha256", "magic_header", "is_executable_bit",
        "suspicious", "reasons"
    ]
    with open(outpath, "w", newline="", encoding="utf-8") as csvf:
        w = csv.writer(csvf)
        w.writerow(keys)
        for r in results:
            w.writerow([r.get(k, "") if k != "reasons" else ";".join(r.get("reasons", [])) for k in keys])


def generate_json_report(results: List[Dict[str, object]], outpath: str) -> None:
    with open(outpath, "w", encoding="utf-8") as jf:
        json.dump(results, jf, indent=2, default=str)
