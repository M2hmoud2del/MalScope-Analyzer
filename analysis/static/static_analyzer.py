import os
import hashlib
from .strings_analyzer import analyze_strings
from .pe_analysis import analyze_pe
from .vt_client import get_vt_report

def calculate_sha256(file_path):
    """
    Calculates the SHA256 hash of a file.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error hashing file {file_path}: {e}")
        return None

def run_static_analysis(file_path):
    """
    Entry point for the Static Analysis Module.
    Aggregates data from different static analysis submodules.
    
    Expected Output Format:
    {
      "hash": "...",
      "urls": [],
      "ips": [],
      "vt_result": "...",
      "pe_info": {...}
    }
    """
    # 1. File Hashing
    file_hash = calculate_sha256(file_path)
    
    # 2. String Extraction
    strings_data = {"urls": [], "ips": []}
    if os.path.exists(file_path):
        strings_data = analyze_strings(file_path)
        
    # 3. VirusTotal Lookup
    vt_result = "Not found in VT"
    if file_hash and file_hash != "Error calculating hash":
        vt_result = get_vt_report(file_hash)
    
    # 4. PE Analysis
    pe_result = {}
    if os.path.exists(file_path):
        pe_result = analyze_pe(file_path)
    
    # Assemble the final result dictionary
    result = {
        "hash": file_hash if file_hash else "Error calculating hash",
        "urls": strings_data.get("urls", []),
        "ips": strings_data.get("ips", []),
        "vt_result": vt_result,
        "pe_info": pe_result
    }
    
    return result