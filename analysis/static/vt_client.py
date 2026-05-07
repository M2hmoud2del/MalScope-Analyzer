import os
import requests
from dotenv import load_dotenv

load_dotenv()

# Load the VirusTotal API Key from the environment
API_KEY = os.environ.get("VT_API_KEY")

def get_vt_report(file_hash):
    """
    Queries the VirusTotal API (v3) to see if a file hash has been flagged.
    Returns a string in the format 'X/Y malicious' or an appropriate error message.
    """
    if not file_hash or file_hash == "Error calculating hash":
        return "Invalid Hash"
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": API_KEY
    }
    
    try:
        # Send GET request with a timeout to prevent hanging if internet is down
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            if not stats:
                return "Not found in VT"
                
            malicious_count = stats.get("malicious", 0)
            total_count = sum(stats.values())
            
            if malicious_count > 0:
                return f"Detections: {malicious_count}/{total_count}"
            else:
                return "Clean"
            
        elif response.status_code == 404:
            # Hash not found on VirusTotal
            return "Not found in VT"
        elif response.status_code == 401:
            return "Invalid Key"
        elif response.status_code == 429:
            return "Key Limit Exceeded"
        else:
            return f"VT API Error ({response.status_code})"
            
    except requests.exceptions.RequestException as e:
        # Handles connection errors, timeouts, etc.
        return "VT Connection Error"
    except Exception as e:
        return f"VT Processing Error"
