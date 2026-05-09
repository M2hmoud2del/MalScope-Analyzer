import re
import requests
import time

# Common noise strings to ignore
BLACKLIST = [
    "pyi_", "_bootstrap", "importlib", "__main__", "__init__",
    "site-packages", "lib-dynload", "base_library.zip", "setuptools",
    "pkg_resources", "_ctypes", "_ssl", "_hashlib", "_bz2", "_lzma",
    "pydantic", "urllib3", "certifi", "charset_normalizer", "idna",
    "requests", "site-packages"
]

def is_meaningful_string(s):
    """
    Checks if a string is likely meaningful text rather than random bytes/noise.
    Applies length, complexity, and blacklist filters.
    """
    if len(s) < 8:
        return False
        
    s_lower = s.lower()
    for blacklisted in BLACKLIST:
        if blacklisted in s_lower:
            return False
            
    # Calculate ratio of alphanumeric characters to filter out pure random symbols
    alnum_count = sum(c.isalnum() for c in s)
    if len(s) > 0 and (alnum_count / len(s)) < 0.6:
        return False
        
    return True

def analyze_strings(file_path):
    """
    Extracts, filters, and categorizes strings.
    Performs geolocation on extracted IPs.
    """
    result = {
        "priority_strings": {
            "urls": [],
            "ips": [],
            "file_paths": [],
            "registry_keys": []
        },
        "general_strings": {
            "ascii": [],
            "unicode": []
        },
        "network_geolocation": {
            "urls": [],
            "ips": []
        }
    }
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            
        # 1. Raw Extraction (Minimum 8 chars)
        ascii_pattern = rb'[ -~]{8,}'
        unicode_pattern = rb'(?:[\x20-\x7E]\x00){8,}'
        
        raw_ascii = re.findall(ascii_pattern, data)
        raw_unicode = re.findall(unicode_pattern, data)
        
        all_strings = set()
        
        # Decode and filter ASCII
        for s in raw_ascii:
            try:
                decoded = s.decode('ascii').strip()
                if is_meaningful_string(decoded):
                    all_strings.add(("ascii", decoded))
            except UnicodeDecodeError:
                pass
                
        # Decode and filter Unicode
        for s in raw_unicode:
            try:
                decoded = s.decode('utf-16le').strip()
                if is_meaningful_string(decoded):
                    all_strings.add(("unicode", decoded))
            except UnicodeDecodeError:
                pass
                
        # 2. Categorization Regexes
        path_pattern = re.compile(r'^(?:[a-zA-Z]:\\[\\\S|*\S]?.*|\/[a-zA-Z0-9_\-]+\/.*)$')
        reg_pattern = re.compile(r'^(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\.*$', re.IGNORECASE)
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        url_pattern = re.compile(r'https?://[a-zA-Z0-9./?=_%:-]+')
        
        for enc_type, s in all_strings:
            is_priority = False
            
            # URLs
            if url_pattern.search(s):
                urls = url_pattern.findall(s)
                for u in urls:
                    result["priority_strings"]["urls"].append(u)
                    result["network_geolocation"]["urls"].append(u)
                is_priority = True
                
            # IPs
            if ip_pattern.search(s):
                ips = ip_pattern.findall(s)
                for ip in ips:
                    parts = ip.split('.')
                    if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                        result["priority_strings"]["ips"].append(ip)
                is_priority = True
                
            # File Paths
            if path_pattern.match(s) or ("\\" in s and "." in s and len(s) < 200):
                # simpler heuristic for Windows paths if regex misses
                if "\\" in s and not any(c in s for c in ['/', '<', '>', '|', '"', '?']):
                    result["priority_strings"]["file_paths"].append(s)
                    is_priority = True
                
            # Registry Keys
            if reg_pattern.match(s) or "SOFTWARE\\" in s.upper():
                result["priority_strings"]["registry_keys"].append(s)
                is_priority = True
                
            # General strings
            if not is_priority:
                result["general_strings"][enc_type].append(s)
                    
        # Deduplication
        result["priority_strings"]["urls"] = list(set(result["priority_strings"]["urls"]))
        result["priority_strings"]["ips"] = list(set(result["priority_strings"]["ips"]))
        result["priority_strings"]["file_paths"] = list(set(result["priority_strings"]["file_paths"]))
        result["priority_strings"]["registry_keys"] = list(set(result["priority_strings"]["registry_keys"]))
        result["network_geolocation"]["urls"] = list(set(result["network_geolocation"]["urls"]))
        
        # 3. Geolocation
        ips_found = result["priority_strings"]["ips"]
        
        for ip in ips_found:
            geo_info = {"ip": ip, "country": "Unknown/Local", "isp": "Unknown"}
            
            if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.30.', '172.31.', '192.168.', '127.', '0.', '169.254.', '224.', '239.', '255.')):
                result["network_geolocation"]["ips"].append(geo_info)
                continue
                
            try:
                time.sleep(0.5) 
                response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp", timeout=5)
                if response.status_code == 200:
                    api_data = response.json()
                    if api_data.get("status") == "success":
                        geo_info["country"] = api_data.get("country", "Unknown")
                        geo_info["isp"] = api_data.get("isp", "Unknown")
            except Exception as e:
                print(f"Geolocation failed for {ip}: {e}")
                
            result["network_geolocation"]["ips"].append(geo_info)

    except Exception as e:
        print(f"Error reading strings from {file_path}: {e}")

    return result
