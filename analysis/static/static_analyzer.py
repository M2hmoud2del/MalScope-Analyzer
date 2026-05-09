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
    """
    # 1. File Hashing
    file_hash = calculate_sha256(file_path)
    
    # 2. String Extraction & Geolocation
    strings_data = {
        "priority_strings": {"urls": [], "ips": [], "file_paths": [], "registry_keys": []},
        "general_strings": {"ascii": [], "unicode": []},
        "network_geolocation": {"urls": [], "ips": []}
    }
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
        "strings": {
            "priority_strings": strings_data.get("priority_strings", {}),
            "general_strings": strings_data.get("general_strings", {})
        },
        "imports_exports": pe_result.get("imports_exports", {"imports": {}, "exports": []}),
        "signature": pe_result.get("signature", {"signed": False, "details": None}),
        "packer_info": pe_result.get("packer_info", {"detected": False, "packers": []}),
        "resources": pe_result.get("resources", []),
        "compile_time": pe_result.get("compile_time", "Unknown"),
        "network_geolocation": strings_data.get("network_geolocation", {"urls": [], "ips": []}),
        "pe_info": {
            "is_pe": pe_result.get("is_pe", False),
            "error": pe_result.get("error"),
            "machine_type": pe_result.get("machine_type"),
            "sections": pe_result.get("sections", []),
            "suspicious_indicators": pe_result.get("suspicious_indicators", [])
        },
        "vt_result": vt_result
    }
    
    return result