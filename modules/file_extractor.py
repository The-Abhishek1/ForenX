import os
from datetime import datetime
from typing import List
import hashlib
import mimetypes
from PIL import Image, ExifTags

def get_hashes(file_path: str) -> dict:
    hashes = {'md5': None, 'sha1': None, 'sha256': None}
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        hashes['error'] = str(e)
    return hashes

def get_exif_data(file_path: str) -> dict:
    exif_info = {}
    try:
        image = Image.open(file_path)
        exif_data = image._getexif()
        if exif_data:
            for tag, value in exif_data.items():
                tag_name = ExifTags.TAGS.get(tag, tag)
                exif_info[tag_name] = str(value)
    except Exception:
        pass  # Not an image or EXIF unavailable
    return exif_info

def is_hidden(file_path: str) -> bool:
    return os.path.basename(file_path).startswith(".")

def _get_metadata(file_path: str) -> str:
    try:
        stats = os.stat(file_path)
        size = stats.st_size
        created = datetime.fromtimestamp(stats.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
        modified = datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

        return f"[FILE] {file_path}\n    Size: {size} bytes\n    Created: {created}\n    Modified: {modified}"
    except Exception as e:
        return f"[ERROR] {file_path}: {e}"
    
    
def _analyze_file(file_path: str) -> str:
    try:
        stats = os.stat(file_path)
        size = stats.st_size
        created = datetime.fromtimestamp(stats.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
        modified = datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        file_type = mimetypes.guess_type(file_path)[0] or "unknown"
        hidden = is_hidden(file_path)
        hashes = get_hashes(file_path)
        exif = get_exif_data(file_path)

        entry = [
            f"[FILE] {file_path}",
            f"    Size: {size} bytes",
            f"    Type: {file_type}",
            f"    Created: {created}",
            f"    Modified: {modified}",
            f"    Hidden: {'Yes' if hidden else 'No'}",
            f"    Hashes:",
            f"        MD5: {hashes['md5']}",
            f"        SHA1: {hashes['sha1']}",
            f"        SHA256: {hashes['sha256']}",
        ]

        if exif:
            entry.append("    EXIF Data:")
            for k, v in exif.items():
                entry.append(f"        {k}: {v[:80]}")

        return "\n".join(entry)

    except Exception as e:
        return f"[ERROR] {file_path}: {e}"
    

def extract_full_metadata(target_path: str) -> List[str]:
    report = []
    if os.path.isfile(target_path):
        report.append(f"[+] Starting scanning on File: {target_path}\n")
        report.append(_analyze_file(target_path))
    else:
        report.append(f"[+] Starting scanning on Directory: {target_path}\n")
        for root, dirs, files in os.walk(target_path):
            for file in files:
                full_path = os.path.join(root, file)
                report.append(_analyze_file(full_path))

    report.append(f"\n")
    return report

