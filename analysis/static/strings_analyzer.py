import re

def analyze_strings(file_path):
    """
    Extracts URLs and IP addresses from a given file.
    Returns a dictionary with 'urls' and 'ips' lists.
    """
    urls_found = set()
    ips_found = set()
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            
        # Basic IPv4 extraction regex
        # This will match xxx.xxx.xxx.xxx where xxx is 1-3 digits
        ip_pattern = rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, data)
        
        for ip in ips:
            try:
                ip_str = ip.decode('utf-8')
                # Validate IP parts
                parts = ip_str.split('.')
                if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                    ips_found.add(ip_str)
            except (UnicodeDecodeError, ValueError):
                continue
                
        # Basic URL extraction regex
        url_pattern = rb'https?://[a-zA-Z0-9./?=_%:-]+'
        urls = re.findall(url_pattern, data)
        
        for url in urls:
            try:
                url_str = url.decode('utf-8')
                urls_found.add(url_str)
            except UnicodeDecodeError:
                continue

    except Exception as e:
        # In case of any read errors (e.g., file not accessible)
        print(f"Error reading strings from {file_path}: {e}")
        pass

    return {
        "urls": list(urls_found),
        "ips": list(ips_found)
    }
