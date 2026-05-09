import os
import hashlib
from .strings_analyzer import analyze_strings
from .pe_analysis import analyze_pe
from .vt_client import get_vt_report

def calculate_hashes(file_path):
    """
    Calculates MD5, SHA-1, SHA-256, and SHA-512 hashes of a file.
    Returns a dictionary of the hashes.
    """
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512()
    }
    try:
        with open(file_path, "rb") as f:
            # Read in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                for hash_obj in hashes.values():
                    hash_obj.update(byte_block)
        
        return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
    except Exception as e:
        print(f"Error hashing file {file_path}: {e}")
        return {name: "Error calculating hash" for name in hashes}

def clean_none_values(data):
    """
    Recursively replaces all None values with empty strings ("")
    to ensure JSON serialization compatibility.
    """
    if isinstance(data, dict):
        return {k: clean_none_values(v if v is not None else "") for k, v in data.items()}
    elif isinstance(data, list):
        return [clean_none_values(v if v is not None else "") for v in data]
    return data if data is not None else ""

def run_static_analysis(file_path):
    """
    Entry point for the Static Analysis Module.
    Aggregates data from different static analysis submodules.
    """
    # 1. File Hashing
    file_hashes = calculate_hashes(file_path)
    
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
    sha256_hash = file_hashes.get("sha256", "Error calculating hash")
    if sha256_hash and sha256_hash != "Error calculating hash":
        vt_result = get_vt_report(sha256_hash)
    
    # 4. PE Analysis
    pe_result = {}
    if os.path.exists(file_path):
        pe_result = analyze_pe(file_path)
        
    # Add imphash to the hashes dictionary
    file_hashes["imphash"] = pe_result.get("imphash", "")
    
    # Assemble the final result dictionary
    result = {
        "hashes": file_hashes,
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
    
    # Clean the results before returning
    cleaned_results = clean_none_values(result)
    
    return cleaned_results